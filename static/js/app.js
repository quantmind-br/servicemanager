(() => {
  "use strict";

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
  // Standard (non-JS) form POSTs carry the token only in the hidden csrf_token
  // field, which Chrome can restore to a stale value on reload/back/bfcache.
  // Reset every hidden field to the freshly-rendered meta token (which the
  // browser does not restore) on load, on pageshow, and right before each submit,
  // so the field always matches the session instead of "tokens do not match".
  const syncCsrfFields = (root) => {
    if (!csrfToken) return;
    for (const field of root.querySelectorAll('input[name="csrf_token"]')) field.value = csrfToken;
  };
  syncCsrfFields(document);
  window.addEventListener("pageshow", () => syncCsrfFields(document));
  document.addEventListener("submit", (event) => {
    if (event.target instanceof HTMLFormElement) syncCsrfFields(event.target);
  }, true);

  const toast = document.getElementById("toast");
  let toastTimer = 0;
  const showToast = (message, kind = "error") => {
    if (!toast) return;
    toast.textContent = message;
    toast.className = kind === "error" ? "toast toast-error" : "toast";
    toast.hidden = false;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => { toast.hidden = true; }, 5000);
  };

  const saveAnnouncer = document.getElementById("save-announcer");
  const announceSave = (message) => {
    if (!saveAnnouncer) return;
    saveAnnouncer.textContent = "";
    window.setTimeout(() => { saveAnnouncer.textContent = message; }, 30);
  };

  // ===== Copy: [data-copy-value] copies a fixed string; [data-copy-input] copies
  // the current value of a referenced input. No insecure/deprecated fallback.
  const flashCopyFeedback = (button, message) => {
    const feedback = button.querySelector(".copy-feedback");
    if (feedback) feedback.textContent = message;
    button.classList.add("is-copied");
    window.setTimeout(() => {
      if (feedback) feedback.textContent = "";
      button.classList.remove("is-copied");
    }, 1500);
  };

  const copyText = async (button, text) => {
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      showToast("Não foi possível copiar.");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      flashCopyFeedback(button, "Copiado");
    } catch {
      showToast("Não foi possível copiar.");
    }
  };

  document.querySelectorAll("[data-copy-value]").forEach((button) => {
    button.addEventListener("click", () => copyText(button, button.dataset.copyValue || ""));
  });
  document.querySelectorAll("[data-copy-input]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.copyInput);
      copyText(button, input ? input.value : "");
    });
  });

  // ===== Password reveal: per-cell state. Each secret cell owns its own
  // AbortController + timer so multiple rows never share a singleton panel.
  const secretState = new Map();

  const restoreMask = (cell) => {
    const state = secretState.get(cell);
    if (state) {
      window.clearTimeout(state.timer);
      window.clearTimeout(state.warnTimer);
      state.controller?.abort();
      secretState.delete(cell);
    }
    const mask = cell.querySelector("[data-secret-mask]");
    if (mask) { mask.textContent = "••••••••"; mask.classList.remove("is-expiring"); }
    const showButton = cell.querySelector("[data-secret-show]");
    if (showButton) showButton.textContent = "Exibir";
  };

  const restoreAllMasks = () => {
    for (const cell of Array.from(secretState.keys())) restoreMask(cell);
  };


  const fetchSecret = async (cell) => {
    const controller = new AbortController();
    const prior = secretState.get(cell);
    if (prior) {
      window.clearTimeout(prior.timer);
      window.clearTimeout(prior.warnTimer);
      prior.controller?.abort();
    }
    secretState.set(cell, { controller, timer: 0 });
    const response = await fetch(cell.dataset.revealUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" },
      signal: controller.signal,
    });
    if (response.redirected && new URL(response.url).pathname === "/login") {
      window.location.assign(response.url);
      return new Promise(() => {});
    }
    if (!response.ok) { const err = new Error("reveal failed"); err.status = response.status; throw err; }
    const payload = await response.json();
    return { controller, value: payload.value, expiresIn: payload.expires_in };
  };

  document.querySelectorAll("[data-secret-show]").forEach((button) => {
    const cell = button.closest("[data-secret-cell]");
    if (!cell) return;
    button.addEventListener("click", async () => {
      if (secretState.has(cell) && secretState.get(cell).revealed) {
        restoreMask(cell);
        return;
      }
      button.disabled = true;
      button.textContent = "…";
      try {
        const { controller, value, expiresIn } = await fetchSecret(cell);
        if (controller.signal.aborted || document.hidden) return;
        const mask = cell.querySelector("[data-secret-mask]");
        if (mask) mask.textContent = value;
        button.textContent = "Ocultar";
        const timer = window.setTimeout(() => restoreMask(cell), Math.min(expiresIn, 30) * 1000 || 30000);
        const warnTimer = window.setTimeout(() => { const m = cell.querySelector("[data-secret-mask]"); if (m) m.classList.add("is-expiring"); }, Math.max((Math.min(expiresIn, 30) - 5) * 1000, 0));
        secretState.set(cell, { controller, timer, warnTimer, revealed: true });
      } catch (error) {
        if (error?.name === "AbortError") return;
        restoreMask(cell);
        showToast(error?.status === 429 ? "Limite de revelações atingido. Aguarde alguns minutos." : "Não foi possível exibir a senha.");
      } finally {
        if (button.textContent === "…") button.textContent = "Exibir";
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-secret-copy]").forEach((button) => {
    const cell = button.closest("[data-secret-cell]");
    if (!cell) return;
    button.addEventListener("click", async () => {
      let ownController = null;
      try {
        const result = await fetchSecret(cell);
        ownController = result.controller;
        if (ownController.signal.aborted) return;
        let value = result.value;
        await navigator.clipboard.writeText(value);
        value = "";
        if (secretState.get(cell)?.controller === ownController) restoreMask(cell);
        flashCopyFeedback(button, "Copiado");
      } catch (error) {
        if (error?.name === "AbortError") return;
        if (!ownController || secretState.get(cell)?.controller === ownController) restoreMask(cell);
        showToast(error?.status === 429 ? "Limite de revelações atingido. Aguarde alguns minutos." : "Não foi possível copiar.")
      }
    });
  });

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) restoreAllMasks();
  });
  window.addEventListener("pagehide", restoreAllMasks);

  // ===== Account edit modal: a single reusable <dialog> filled per-row.
  const editDialog = document.getElementById("account-edit-dialog");
  const editForm = editDialog?.querySelector("[data-edit-form]");
  const closeEditDialog = () => {
    if (!editDialog || !editForm) return;
    if (editDialog.open) editDialog.close();
    editForm.removeAttribute("action");
    editForm.email.value = "";
    editForm.password.value = "";
  };
  if (editDialog && editForm) {
    document.querySelectorAll("[data-edit-account]").forEach((button) => {
      button.addEventListener("click", () => {
        editForm.setAttribute("action", button.dataset.updateUrl);
        editForm.email.value = button.dataset.accountEmail || "";
        editForm.dataset.initialEmail = button.dataset.accountEmail || "";
        editForm.password.value = "";
        syncCsrfFields(editForm);
        editDialog.showModal();
      });
    });
    const requestCloseEditDialog = () => {
      const dirty =
        editForm.email.value !== (editForm.dataset.initialEmail || "") ||
        editForm.password.value !== "";
      if (!dirty) { closeEditDialog(); return; }
      askConfirm("Descartar alterações?").then((ok) => { if (ok) closeEditDialog(); });
    };
    editDialog.querySelector("[data-edit-cancel]")?.addEventListener("click", requestCloseEditDialog);
    editDialog.addEventListener("cancel", (event) => { event.preventDefault(); requestCloseEditDialog(); });
    editDialog.addEventListener("click", (event) => {
      if (event.target === editDialog) requestCloseEditDialog();
    });
  }

  const confirmDialog = document.getElementById("confirm-dialog");
  const askConfirm = (message) => {
    if (!confirmDialog) return Promise.resolve(window.confirm(message));
    return new Promise((resolve) => {
      confirmDialog.querySelector("[data-confirm-message]").textContent = message;
      const settle = (value) => {
        confirmDialog.removeEventListener("cancel", onCancel);
        accept.removeEventListener("click", onAccept);
        cancel.removeEventListener("click", onCancel);
        if (confirmDialog.open) confirmDialog.close();
        resolve(value);
      };
      const onAccept = () => settle(true);
      const onCancel = (event) => { event.preventDefault(); settle(false); };
      const accept = confirmDialog.querySelector("[data-confirm-accept]");
      const cancel = confirmDialog.querySelector("[data-confirm-cancel]");
      accept.addEventListener("click", onAccept);
      cancel.addEventListener("click", onCancel);
      confirmDialog.addEventListener("cancel", onCancel);
      confirmDialog.showModal();
    });
  };

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.confirm && form.dataset.confirmed !== "1") {
      event.preventDefault();
      askConfirm(form.dataset.confirm).then((ok) => {
        if (!ok) return;
        form.dataset.confirmed = "1";
        form.requestSubmit();
      });
      return;
    }
    delete form.dataset.confirmed;
    if (form.hasAttribute("data-no-submit-lock")) return;
    if (form.dataset.submitting) { event.preventDefault(); return; }
    form.dataset.submitting = "1";
    const button = form.querySelector('button[type="submit"]');
    if (button) {
      button.dataset.label = button.textContent;
      button.disabled = true;
      button.textContent = "Enviando…";
    }
  });
  window.addEventListener("pageshow", () => {
    document.querySelectorAll("form[data-submitting]").forEach((form) => {
      delete form.dataset.submitting;
      const button = form.querySelector("button[disabled][data-label]");
      if (button) { button.disabled = false; button.textContent = button.dataset.label; }
    });
  });

  document.querySelectorAll("form[data-async-form]").forEach((form) => {
    const errorBox = form.querySelector("[data-form-error]");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (form.dataset.submitting) return;
      form.dataset.submitting = "1";
      const button = form.querySelector('button[type="submit"]');
      const label = button ? button.textContent : "";
      if (button) { button.disabled = true; button.textContent = "Enviando…"; }
      if (errorBox) { errorBox.hidden = true; errorBox.textContent = ""; }
      try {
        const response = await fetch(form.action, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" },
          body: new URLSearchParams(new FormData(form)),
        });
        if (response.redirected) { window.location.assign(response.url); return; }
        const payload = response.status === 400 ? await response.json().catch(() => null) : null;
        if (payload && payload.error && errorBox) { errorBox.textContent = payload.error; errorBox.hidden = false; }
        else showToast("Não foi possível salvar. Tente novamente.");
      } catch {
        showToast("Não foi possível salvar. Tente novamente.");
      } finally {
        delete form.dataset.submitting;
        if (button) { button.disabled = false; button.textContent = label; }
      }
    });
  });

  // ===== Filters: fuzzy text (accent/case-insensitive subsequence over each
  // row's data-search) AND'd with the Status and Cadastro column selects.
  const normalize = (text) =>
    (text || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();

  const subsequenceMatch = (needle, hay) => {
    if (!needle) return true;
    let i = 0;
    for (let k = 0; k < hay.length && i < needle.length; k++) {
      if (hay[k] === needle[i]) i++;
    }
    return i === needle.length;
  };

  let refreshFilter = () => {};
  let refreshStatusLabel = () => {};
  const filterInput = document.getElementById("account-filter");
  const statusFilter = document.getElementById("filter-status");
  const registeredFilter = document.getElementById("filter-registered");
  const accountsTbody = document.querySelector("table.accounts tbody");
  if (accountsTbody && (filterInput || statusFilter || registeredFilter)) {
    const rowInfo = Array.from(accountsTbody.querySelectorAll("tr[data-row]")).map((tr) => ({
      tr,
      search: normalize(tr.dataset.search || ""),
      statusLabel: normalize(tr.querySelector(".status-badge")?.selectedOptions[0]?.textContent || ""),
      detail: document.getElementById("detail-" + tr.dataset.id),
    }));
    const infoByRow = new Map(rowInfo.map((info) => [info.tr, info]));
    const noResults = accountsTbody.querySelector("tr.no-results");
    const applyFilter = () => {
      const query = normalize((filterInput?.value || "").trim());
      const status = statusFilter?.value || "";
      const registered = registeredFilter?.value || "";
      let visible = 0;
      for (const info of rowInfo) {
        const haystack = info.search + " " + info.statusLabel;
        const show =
          subsequenceMatch(query, haystack) &&
          (!status || info.tr.dataset.status === status) &&
          (!registered || info.tr.dataset.registered === registered);
        info.tr.hidden = !show;
        if (!show && info.detail) info.detail.hidden = true;
        if (show) visible += 1;
      }
      if (noResults) noResults.hidden = visible !== 0;
      const active = Boolean(query || status || registered);
      const countEl = document.getElementById("filter-count");
      if (countEl) countEl.textContent = active ? `Exibindo ${visible} de ${rowInfo.length} contas` : "";
      const clearButton = document.getElementById("filter-clear");
      if (clearButton) clearButton.hidden = !active;
    };
    refreshFilter = applyFilter;
    refreshStatusLabel = (tr) => {
      const info = infoByRow.get(tr);
      if (info) info.statusLabel = normalize(tr.querySelector(".status-badge")?.selectedOptions[0]?.textContent || "");
    };
    filterInput?.addEventListener("input", applyFilter);
    statusFilter?.addEventListener("change", applyFilter);
    registeredFilter?.addEventListener("change", applyFilter);
    document.getElementById("filter-clear")?.addEventListener("click", () => {
      if (filterInput) filterInput.value = "";
      if (statusFilter) statusFilter.value = "";
      if (registeredFilter) registeredFilter.value = "";
      applyFilter();
    });
    applyFilter();
  }

  const statusRank = { ativo: 0, nunca: 1, inativo: 2 };
  document.querySelectorAll(".th-sort").forEach((button) => {
    button.addEventListener("click", () => {
      const th = button.closest("th");
      const table = button.closest("table");
      const tbody = table ? table.querySelector("tbody") : null;
      if (!th || !tbody) return;
      const direction = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
      table.querySelectorAll("th[data-sort-col]").forEach((other) => {
        other.setAttribute("aria-sort", other === th ? direction : "none");
      });
      const key = button.dataset.sort;
      const value = (tr) => key === "status"
        ? (statusRank[tr.dataset.status] ?? 1)
        : (tr.querySelector(".email-text")?.textContent || "").toLowerCase();
      const rows = Array.from(tbody.querySelectorAll("tr[data-row]"));
      rows.sort((a, b) => {
        const va = value(a); const vb = value(b);
        return (va < vb ? -1 : va > vb ? 1 : 0) * (direction === "ascending" ? 1 : -1);
      });
      const anchor = tbody.querySelector("tr.no-results");
      for (const tr of rows) {
        tbody.insertBefore(tr, anchor);
        const detail = document.getElementById("detail-" + tr.dataset.id);
        if (detail) tbody.insertBefore(detail, anchor);
      }
    });
  });

  // ===== Row expansion: [data-expand] toggles the paired detail row.
  document.querySelectorAll("[data-expand]").forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.getAttribute("aria-controls");
      const target = targetId ? document.getElementById(targetId) : null;
      if (!target) return;
      const willOpen = target.hidden;
      target.hidden = !willOpen;
      button.setAttribute("aria-expanded", willOpen ? "true" : "false");
      button.classList.toggle("is-open", willOpen);
    });
  });

  const rowHash = /^#row-(\d+)$/.exec(window.location.hash);
  if (rowHash) {
    const row = document.getElementById("row-" + rowHash[1]);
    const detail = document.getElementById("detail-" + rowHash[1]);
    const expandButton = row ? row.querySelector("[data-expand]") : null;
    if (expandButton && detail && detail.hidden) expandButton.click();
    if (row) row.scrollIntoView({ block: "center" });
  }

  // ===== Auto-submit: [data-autosubmit] controls POST their form on change.

  const controlValue = (control) =>
    control.type === "checkbox" ? (control.checked ? "1" : "0") : control.value;

  const bumpCount = (status, delta) => {
    const el = document.querySelector(`[data-count="${status}"]`);
    if (el) el.textContent = String(Math.max(0, (parseInt(el.textContent, 10) || 0) + delta));
  };

  document.querySelectorAll("[data-autosubmit]").forEach((control) => {
    control.dataset.prev = controlValue(control);
    control.addEventListener("change", async () => {
      const form = control.closest("form");
      if (!form) return;
      if (!form.hasAttribute("data-fetch-update")) {
        if (typeof form.requestSubmit === "function") form.requestSubmit();
        else form.submit();
        return;
      }
      const previous = control.dataset.prev;
      const value = controlValue(control);
      const body = new URLSearchParams(new FormData(form));
      control.disabled = true;
      try {
        const response = await fetch(form.action, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrfToken },
          body,
        });
        if (response.redirected && new URL(response.url).pathname === "/login") {
          window.location.assign(response.url);
          return;
        }
        if (!response.ok) throw new Error("update failed");
        control.dataset.prev = value;
        const row = form.closest("tr[data-row]");
        if (control.name === "status" && row) {
          bumpCount(row.dataset.status, -1);
          bumpCount(value, 1);
          row.dataset.status = value;
          const pill = form.querySelector(".status-pill");
          if (pill) pill.className = "status-pill status-" + value;
          const label = control.selectedOptions[0]?.textContent || value;
          const copyButton = form.querySelector("[data-copy-value]");
          if (copyButton) copyButton.dataset.copyValue = label;
          refreshStatusLabel(row);
          refreshFilter();
          announceSave("Status salvo.");
        } else if (control.name === "registered" && row) {
          row.dataset.registered = value;
          const copyButton = form.querySelector("[data-copy-value]");
          if (copyButton) copyButton.dataset.copyValue = value === "1" ? "Cadastrada" : "Não cadastrada";
          refreshFilter();
          announceSave("Cadastro salvo.");
        }
      } catch {
        if (control.type === "checkbox") control.checked = previous === "1";
        else control.value = previous;
        showToast("Não foi possível salvar. Tente novamente.");
      } finally {
        control.disabled = false;
      }
    });
  });

  // ===== Password visibility toggles.
  document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    const input = button.closest(".password-field")?.querySelector("input");
    if (!input) return;
    button.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      button.setAttribute("aria-pressed", show ? "true" : "false");
      button.setAttribute("aria-label", show ? "Ocultar senha" : "Mostrar senha");
    });
  });

  const feedbackBanner = document.querySelector("[data-feedback]");
  if (feedbackBanner) {
    const url = new URL(window.location.href);
    const isError = url.searchParams.has("error");
    const hadFeedbackParam = url.searchParams.has("ok") || isError || url.searchParams.has("added") || url.searchParams.has("skipped");
    if (hadFeedbackParam) {
      for (const param of ["ok", "added", "skipped", "error"]) url.searchParams.delete(param);
      window.history.replaceState(null, "", url);
      if (!isError) window.setTimeout(() => { feedbackBanner.hidden = true; }, 6000);
    }
  }

})();

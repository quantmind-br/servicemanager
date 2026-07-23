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

  const toast = document.getElementById("toast") || (() => {
    const element = document.createElement("div");
    element.id = "toast";
    element.className = "toast";
    element.setAttribute("role", "alert");
    element.hidden = true;
    document.body.append(element);
    return element;
  })();
  let toastTimer = 0;
  const showToast = (message, kind = "error") => {
    if (!toast) return;
    toast.textContent = message;
    toast.className = kind === "error" ? "toast toast-error" : "toast";
    toast.hidden = false;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => { toast.hidden = true; }, 5000);
  };

  const saveAnnouncer = document.getElementById("save-announcer") || (() => {
    const element = document.createElement("span");
    element.id = "save-announcer";
    element.className = "sr-only";
    element.setAttribute("aria-live", "polite");
    document.body.append(element);
    return element;
  })();
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
    if (showButton) { showButton.classList.remove("is-revealed", "is-loading"); showButton.disabled = false; showButton.setAttribute("aria-label", "Exibir senha"); showButton.setAttribute("title", "Exibir senha"); }
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
      button.classList.add("is-loading");
      try {
        const { controller, value, expiresIn } = await fetchSecret(cell);
        if (controller.signal.aborted || document.hidden) return;
        const mask = cell.querySelector("[data-secret-mask]");
        if (mask) mask.textContent = value;
        button.classList.remove("is-loading");
        button.classList.add("is-revealed");
        button.setAttribute("aria-label", "Ocultar senha");
        button.setAttribute("title", "Ocultar senha");
        const timer = window.setTimeout(() => restoreMask(cell), Math.min(expiresIn, 30) * 1000 || 30000);
        const warnTimer = window.setTimeout(() => { const m = cell.querySelector("[data-secret-mask]"); if (m) m.classList.add("is-expiring"); }, Math.max((Math.min(expiresIn, 30) - 5) * 1000, 0));
        secretState.set(cell, { controller, timer, warnTimer, revealed: true });
      } catch (error) {
        if (error?.name === "AbortError") return;
        restoreMask(cell);
        showToast(error?.status === 429 ? "Limite de revelações atingido. Aguarde alguns minutos." : "Não foi possível exibir a senha.");
      } finally {
        button.classList.remove("is-loading");
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

  // ===== Service preferences modal: atomic server persistence for order and initial service.
  const servicePreferencesDialog = document.getElementById("service-preferences-dialog");
  const servicePreferencesForm = servicePreferencesDialog?.querySelector("[data-service-preferences-form]");
  const serviceOrderList = servicePreferencesForm?.querySelector("[data-service-order-list]");
  const initialServiceSelect = servicePreferencesForm?.querySelector("#initial-service-id");
  let servicePreferencesSnapshot = null;
  if (servicePreferencesDialog && servicePreferencesForm && serviceOrderList && initialServiceSelect) {
    const orderedItems = () => Array.from(serviceOrderList.querySelectorAll("[data-service-order-item]"));
    const syncServiceOrderButtons = () => {
      const items = orderedItems();
      items.forEach((item, index) => {
        item.querySelector('[data-move-service="up"]').disabled = index === 0;
        item.querySelector('[data-move-service="down"]').disabled = index === items.length - 1;
      });
    };
    const serviceOrder = () => orderedItems().map((item) => item.dataset.serviceId);
    const restoreServicePreferences = () => {
      if (!servicePreferencesSnapshot) return;
      for (const id of servicePreferencesSnapshot.order) {
        const item = serviceOrderList.querySelector(`[data-service-id="${id}"]`);
        const option = initialServiceSelect.querySelector(`option[value="${id}"]`);
        if (item) serviceOrderList.append(item);
        if (option) initialServiceSelect.append(option);
      }
      initialServiceSelect.value = servicePreferencesSnapshot.initial;
      syncServiceOrderButtons();
    };
    const closeServicePreferences = () => {
      if (servicePreferencesForm.dataset.submitting) return;
      restoreServicePreferences();
      if (servicePreferencesDialog.open) servicePreferencesDialog.close();
    };
    document.querySelector("[data-service-preferences-open]")?.addEventListener("click", () => {
      servicePreferencesSnapshot = { order: serviceOrder(), initial: initialServiceSelect.value };
      syncCsrfFields(servicePreferencesForm);
      servicePreferencesDialog.showModal();
    });
    servicePreferencesForm.addEventListener("click", (event) => {
      const button = event.target.closest("[data-move-service]");
      if (!button) return;
      const item = button.closest("[data-service-order-item]");
      const sibling = button.dataset.moveService === "up" ? item.previousElementSibling : item.nextElementSibling;
      if (!sibling) return;
      if (button.dataset.moveService === "up") serviceOrderList.insertBefore(item, sibling);
      else serviceOrderList.insertBefore(sibling, item);
      const option = initialServiceSelect.querySelector(`option[value="${item.dataset.serviceId}"]`);
      const siblingOption = initialServiceSelect.querySelector(`option[value="${sibling.dataset.serviceId}"]`);
      if (option && siblingOption) {
        if (button.dataset.moveService === "up") initialServiceSelect.insertBefore(option, siblingOption);
        else initialServiceSelect.insertBefore(siblingOption, option);
      }
      syncServiceOrderButtons();
      (button.disabled ? item.querySelector(`[data-move-service="${button.dataset.moveService === "up" ? "down" : "up"}"]`) : button)?.focus();
    });
    servicePreferencesForm.querySelector("[data-service-preferences-cancel]")?.addEventListener("click", closeServicePreferences);
    servicePreferencesDialog.addEventListener("cancel", (event) => { event.preventDefault(); closeServicePreferences(); });
    servicePreferencesDialog.addEventListener("click", (event) => {
      if (event.target === servicePreferencesDialog) closeServicePreferences();
    });
    servicePreferencesForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (servicePreferencesForm.dataset.submitting) return;
      const body = new URLSearchParams(new FormData(servicePreferencesForm));
      servicePreferencesForm.dataset.submitting = "1";
      const controls = Array.from(servicePreferencesForm.querySelectorAll("button, select"));
      const submitButton = servicePreferencesForm.querySelector('button[type="submit"]');
      controls.forEach((control) => { control.disabled = true; });
      if (submitButton) submitButton.textContent = "Salvando…";
      try {
        const response = await fetch(servicePreferencesForm.action, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrfToken },
          body,
        });
        if (response.redirected && new URL(response.url).pathname === "/login") {
          window.location.assign(response.url);
          return;
        }
        if (response.status === 204) {
          const chips = document.querySelector(".service-chips");
          if (chips) {
            for (const id of serviceOrder()) {
              const chip = chips.querySelector(`[data-service-chip][data-service-id="${id}"]`);
              if (chip) chips.append(chip);
            }
          }
          servicePreferencesSnapshot = { order: serviceOrder(), initial: initialServiceSelect.value };
          servicePreferencesDialog.close();
          announceSave("Preferências de serviços salvas.");
        } else if (response.status === 400) {
          showToast("Preferências de serviços inválidas.");
        } else {
          showToast("Não foi possível salvar as preferências.");
        }
      } catch {
        showToast("Não foi possível salvar as preferências.");
      } finally {
        delete servicePreferencesForm.dataset.submitting;
        controls.forEach((control) => { control.disabled = false; });
        syncServiceOrderButtons();
        if (submitButton) submitButton.textContent = "Salvar preferências";
      }
    });
  }


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
  let refreshBulkSelection = () => {};
  const filterInput = document.getElementById("account-filter");
  const statusFilter = document.getElementById("filter-status");
  const registeredFilter = document.getElementById("filter-registered");
  const rotationFilter = document.getElementById("filter-rotation");
  const accountsTbody = document.querySelector("table.accounts tbody");
  let filterUrlTimer = 0;
  const syncUrlState = () => {
    const url = new URL(window.location.href);
    const values = {
      q: (filterInput?.value || "").trim(),
      st: statusFilter?.value || "",
      reg: registeredFilter?.value || "",
      rot: rotationFilter?.value || "",
    };
    for (const [key, value] of Object.entries(values)) {
      if (value) url.searchParams.set(key, value);
      else url.searchParams.delete(key);
    }
    const sorted = document.querySelector('th[data-sort-col][aria-sort]:not([aria-sort="none"])');
    const sortButton = sorted?.querySelector(".th-sort");
    if (sortButton?.dataset.sort) {
      url.searchParams.set("sort", sortButton.dataset.sort);
      url.searchParams.set("dir", sorted.getAttribute("aria-sort") === "descending" ? "desc" : "asc");
    } else {
      url.searchParams.delete("sort");
      url.searchParams.delete("dir");
    }
    window.history.replaceState(null, "", url);
  };

  if (accountsTbody && (filterInput || statusFilter || registeredFilter || rotationFilter)) {
    const rowInfo = Array.from(accountsTbody.querySelectorAll("tr[data-row]")).map((tr) => ({
      tr,
      search: normalize(tr.dataset.search || ""),
      statusLabel: normalize(tr.querySelector(".status-badge")?.selectedOptions[0]?.textContent || ""),
      detail: document.getElementById("detail-" + tr.dataset.id),
    }));
    const infoByRow = new Map(rowInfo.map((info) => [info.tr, info]));
    const noResults = accountsTbody.querySelector("tr.no-results");
    const applyFilter = (urlDelay = 0) => {
      const query = normalize((filterInput?.value || "").trim());
      const status = statusFilter?.value || "";
      const registered = registeredFilter?.value || "";
      const rotation = rotationFilter?.value || "";
      let visible = 0;
      for (const info of rowInfo) {
        const haystack = info.search + " " + info.statusLabel;
        // All active filters combine (AND); rotation is one more predicate.
        const show =
          subsequenceMatch(query, haystack) &&
          (!status || info.tr.dataset.status === status) &&
          (!registered || info.tr.dataset.registered === registered) &&
          (!rotation || info.tr.dataset.rotation === rotation);
        info.tr.hidden = !show;
        if (!show && info.detail) info.detail.hidden = true;
        if (show) visible += 1;
      }
      if (noResults) noResults.hidden = visible !== 0;
      const active = Boolean(query || status || registered || rotation);
      const countEl = document.getElementById("filter-count");
      if (countEl) countEl.textContent = active ? `Exibindo ${visible} de ${rowInfo.length} contas` : "";
      const clearButton = document.getElementById("filter-clear");
      if (clearButton) clearButton.hidden = !active;
      refreshBulkSelection();
      window.clearTimeout(filterUrlTimer);
      filterUrlTimer = window.setTimeout(syncUrlState, urlDelay);
    };
    refreshFilter = applyFilter;
    refreshStatusLabel = (tr) => {
      const info = infoByRow.get(tr);
      if (info) info.statusLabel = normalize(tr.querySelector(".status-badge")?.selectedOptions[0]?.textContent || "");
    };
    filterInput?.addEventListener("input", () => applyFilter(300));
    statusFilter?.addEventListener("change", () => applyFilter());
    registeredFilter?.addEventListener("change", () => applyFilter());
    rotationFilter?.addEventListener("change", () => applyFilter());
    document.getElementById("filter-clear")?.addEventListener("click", () => {
      if (filterInput) filterInput.value = "";
      if (statusFilter) statusFilter.value = "";
      if (registeredFilter) registeredFilter.value = "";
      if (rotationFilter) rotationFilter.value = "";
      applyFilter();
    });
    const initialParams = new URLSearchParams(window.location.search);
    if (filterInput) filterInput.value = initialParams.get("q") || "";
    if (statusFilter && Array.from(statusFilter.options).some((option) => option.value === initialParams.get("st"))) statusFilter.value = initialParams.get("st") || "";
    if (registeredFilter && Array.from(registeredFilter.options).some((option) => option.value === initialParams.get("reg"))) registeredFilter.value = initialParams.get("reg") || "";
    if (rotationFilter && Array.from(rotationFilter.options).some((option) => option.value === initialParams.get("rot"))) rotationFilter.value = initialParams.get("rot") || "";
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
      syncUrlState();
    });
  });

  const initialSortParams = new URLSearchParams(window.location.search);
  const initialSort = initialSortParams.get("sort");
  const initialDir = initialSortParams.get("dir");
  if (["email", "status"].includes(initialSort)) {
    const button = document.querySelector(`.th-sort[data-sort="${initialSort}"]`);
    button?.click();
    if (initialDir === "desc") button?.click();
  }

  document.getElementById("share-view")?.addEventListener("click", async () => {
    syncUrlState();
    try {
      await navigator.clipboard.writeText(window.location.href);
      showToast("Link copiado.", "success");
    } catch {
      showToast("Não foi possível copiar.");
    }
  });

  // ===== Bulk selection and submissions.
  const selectedAccountIds = new Set();
  const rowSelects = Array.from(document.querySelectorAll("[data-row-select]"));
  const selectVisible = document.getElementById("select-visible");
  const bulkBar = document.getElementById("bulk-bar");
  const bulkCount = document.getElementById("bulk-count");
  const updateBulkUi = () => {
    if (bulkBar) bulkBar.hidden = selectedAccountIds.size === 0;
    if (bulkCount) {
      const total = selectedAccountIds.size;
      const visible = rowSelects.filter(
        (control) => selectedAccountIds.has(control.value) && !control.closest("tr[data-row]")?.hidden,
      ).length;
      bulkCount.textContent = visible < total ? `${total} selecionadas · ${visible} visíveis` : `${total} selecionadas`;
    }
    for (const control of rowSelects) control.checked = selectedAccountIds.has(control.value);
    const visibleControls = rowSelects.filter((control) => !control.closest("tr[data-row]")?.hidden);
    if (selectVisible) {
      selectVisible.checked = visibleControls.length > 0 && visibleControls.every((control) => selectedAccountIds.has(control.value));
      selectVisible.indeterminate = visibleControls.some((control) => selectedAccountIds.has(control.value)) && !selectVisible.checked;
    }
  };
  // Selection is memory-only and MUST survive rows being hidden by filters/sort.
  refreshBulkSelection = () => {
    updateBulkUi();
  };
  rowSelects.forEach((control) => {
    control.addEventListener("change", () => {
      if (control.checked) selectedAccountIds.add(control.value);
      else selectedAccountIds.delete(control.value);
      updateBulkUi();
    });
  });
  selectVisible?.addEventListener("change", () => {
    for (const control of rowSelects) {
      if (control.closest("tr[data-row]")?.hidden) continue;
      if (selectVisible.checked) selectedAccountIds.add(control.value);
      else selectedAccountIds.delete(control.value);
    }
    updateBulkUi();
  });
  const submitBulk = (action, extra = {}) => {
    if (!selectedAccountIds.size) return;
    const serviceId = document.querySelector('input[name="service_id"]')?.value;
    if (!serviceId) return;
    const form = document.createElement("form");
    form.method = "post";
    form.action = action;
    const fields = { csrf_token: csrfToken, service_id: serviceId, ...extra };
    for (const [name, value] of Object.entries(fields)) {
      const input = document.createElement("input");
      input.type = "hidden"; input.name = name; input.value = value;
      form.append(input);
    }
    for (const accountId of selectedAccountIds) {
      const input = document.createElement("input");
      input.type = "hidden"; input.name = "account_ids"; input.value = accountId;
      form.append(input);
    }
    document.body.append(form);
    form.submit();
  };
  document.getElementById("bulk-apply-status")?.addEventListener("click", () => {
    submitBulk("/accounts/bulk/status", { status: document.getElementById("bulk-status")?.value || "" });
  });
  document.getElementById("bulk-registered-on")?.addEventListener("click", () => submitBulk("/accounts/bulk/registered", { registered: "1" }));
  document.getElementById("bulk-registered-off")?.addEventListener("click", () => submitBulk("/accounts/bulk/registered", { registered: "0" }));
  document.getElementById("bulk-apply-field")?.addEventListener("click", () => {
    const fieldId = document.getElementById("bulk-field-id")?.value || "";
    const fieldValue = document.getElementById("bulk-field-value")?.value || "";
    if (!fieldId) { showToast("Selecione um campo."); return; }
    if (!fieldValue) { showToast("Informe um valor."); return; }
    submitBulk("/accounts/bulk/field", { field_id: fieldId, field_value: fieldValue });
  });
  const deleteDialog = document.getElementById("delete-confirm-dialog");
  const deleteInput = document.getElementById("delete-confirm-input");
  const deleteAccept = document.getElementById("delete-confirm-accept");
  const deleteInstruction = document.getElementById("delete-confirm-instruction");
  document.getElementById("bulk-delete")?.addEventListener("click", () => {
    if (!selectedAccountIds.size || !deleteDialog) return;
    const count = selectedAccountIds.size;
    if (deleteInstruction) deleteInstruction.textContent = `Digite ${count} para confirmar`;
    if (deleteInput) deleteInput.value = "";
    if (deleteAccept) deleteAccept.disabled = true;
    deleteDialog.showModal();
  });
  deleteInput?.addEventListener("input", () => {
    const trimmed = deleteInput.value.trim();
    if (deleteAccept) deleteAccept.disabled = trimmed !== String(selectedAccountIds.size);
  });
  document.getElementById("delete-confirm-cancel")?.addEventListener("click", () => deleteDialog?.close());
  deleteDialog?.addEventListener("cancel", (event) => { event.preventDefault(); deleteDialog.close(); });
  deleteAccept?.addEventListener("click", () => {
    if (deleteInput?.value.trim() !== String(selectedAccountIds.size)) return;
    submitBulk("/accounts/bulk/delete", { confirmation_count: String(selectedAccountIds.size) });
  });
  updateBulkUi();

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


  // ===== Reauthentication: preserve a safe local return path after the
  // server's pinned 204 response.
  const reauthForm = document.querySelector('form[action$="/reauth"]');
  reauthForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    const button = reauthForm.querySelector('button[type="submit"]');
    const label = button?.textContent || "Confirmar";
    if (button) { button.disabled = true; button.textContent = "Enviando…"; }
    try {
      const response = await fetch(reauthForm.action, {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRFToken": csrfToken },
        body: new URLSearchParams(new FormData(reauthForm)),
      });
      if (response.redirected && new URL(response.url).pathname === "/login") {
        window.location.assign(response.url);
        return;
      }
      if (response.status === 204) {
        const next = new URLSearchParams(window.location.search).get("next") || "/";
        window.location.assign(next.startsWith("/") && !next.startsWith("//") ? next : "/");
        return;
      }
      if (response.status === 401) showToast("Credenciais inválidas.");
      else if (response.status === 429) showToast("Muitas tentativas. Aguarde alguns minutos.");
      else showToast("Não foi possível confirmar sua identidade.");
    } catch {
      showToast("Não foi possível confirmar sua identidade.");
    } finally {
      if (button) { button.disabled = false; button.textContent = label; }
    }
  });

  // ===== User administration.
  const adminFetch = async (url, body) => {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken },
      body,
    });
    if (response.redirected && new URL(response.url).pathname === "/login") {
      window.location.assign(response.url);
      return null;
    }
    if (response.status === 403) {
      window.location.assign("/reauth?next=" + encodeURIComponent(window.location.pathname + window.location.search + window.location.hash));
      return null;
    }
    return response;
  };

  document.querySelectorAll("[data-admin-role]").forEach((select) => {
    select.dataset.prev = select.value;
    select.addEventListener("change", async () => {
      const previous = select.dataset.prev;
      select.disabled = true;
      try {
        const response = await adminFetch(`/admin/users/${select.dataset.userId}/role`, new URLSearchParams({ role: select.value }));
        if (!response) return;
        if (response.status === 204) {
          select.dataset.prev = select.value;
          announceSave("Papel atualizado.");
        } else if (response.status === 400) {
          showToast((await response.text()) || "Papel inválido.");
          select.value = previous;
        } else {
          throw new Error("admin role failed");
        }
      } catch {
        select.value = previous;
        showToast("Não foi possível atualizar o papel.");
      } finally {
        select.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-admin-active]").forEach((control) => {
    control.dataset.prev = control.checked ? "1" : "0";
    control.addEventListener("change", async () => {
      const previous = control.dataset.prev;
      control.disabled = true;
      try {
        const response = await adminFetch(`/admin/users/${control.dataset.userId}/active`, new URLSearchParams({ is_active: control.checked ? "1" : "0" }));
        if (!response) return;
        if (response.status === 204) {
          control.dataset.prev = control.checked ? "1" : "0";
          announceSave("Acesso atualizado.");
        } else if (response.status === 400) {
          showToast((await response.text()) || "Alteração inválida.");
          control.checked = previous === "1";
        } else {
          throw new Error("admin active failed");
        }
      } catch {
        control.checked = previous === "1";
        showToast("Não foi possível atualizar o acesso.");
      } finally {
        control.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-membership-role]").forEach((select) => {
    select.dataset.prev = select.value;
    select.addEventListener("change", async () => {
      const previous = select.dataset.prev;
      const serviceId = select.dataset.serviceId;
      const userId = select.dataset.userId;
      select.disabled = true;
      try {
        const url = select.value
          ? `/admin/service-access/${serviceId}/${userId}`
          : `/admin/service-access/${serviceId}/${userId}/delete`;
        const body = select.value ? new URLSearchParams({ role: select.value }) : new URLSearchParams();
        const response = await adminFetch(url, body);
        if (!response) return;
        if (response.status === 204) {
          select.dataset.prev = select.value;
          announceSave("Acesso atualizado.");
        } else if (response.status === 400) {
          showToast((await response.text()) || "Acesso inválido.");
          select.value = previous;
        } else if (response.status === 404) {
          select.value = previous;
        } else {
          throw new Error("membership change failed");
        }
      } catch {
        select.value = previous;
        showToast("Não foi possível atualizar o acesso.");
      } finally {
        select.disabled = false;
      }
    });
  });

  const adminCreateForm = document.querySelector("[data-admin-create]");
  const tempPasswordDialog = document.getElementById("temp-password-dialog");
  adminCreateForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    const button = adminCreateForm.querySelector('button[type="submit"]');
    const label = button?.textContent || "Criar";
    if (button) { button.disabled = true; button.textContent = "Enviando…"; }
    try {
      const response = await adminFetch(adminCreateForm.action, new URLSearchParams(new FormData(adminCreateForm)));
      if (!response) return;
      if (response.status === 201) {
        const payload = await response.json();
        const input = document.getElementById("temp-password-value");
        const code = tempPasswordDialog?.querySelector("[data-temp-password]");
        if (input) input.value = payload.temporary_password || "";
        if (code) code.textContent = payload.temporary_password || "";
        tempPasswordDialog?.showModal();
      } else if (response.status === 409) {
        showToast("Login indisponível.");
      } else if (response.status === 400) {
        showToast("Usuário inválido.");
      } else {
        throw new Error("admin create failed");
      }
    } catch {
      showToast("Não foi possível criar o usuário.");
    } finally {
      if (button) { button.disabled = false; button.textContent = label; }
    }
  });

  const dismissTempPassword = () => {
    if (!tempPasswordDialog) return;
    const input = document.getElementById("temp-password-value");
    const code = tempPasswordDialog.querySelector("[data-temp-password]");
    if (input) input.value = "";
    if (code) code.textContent = "";
    if (tempPasswordDialog.open) tempPasswordDialog.close();
    window.location.reload();
  };
  tempPasswordDialog?.querySelector("[data-temp-dismiss]")?.addEventListener("click", dismissTempPassword);
  tempPasswordDialog?.addEventListener("cancel", (event) => {
    event.preventDefault();
    dismissTempPassword();
  });

  // ===== Security integrations (webhooks): async CRUD + one-time signing secret.
  const webhookSecretDialog = document.getElementById("webhook-secret-dialog");
  const clearWebhookSecret = () => {
    if (!webhookSecretDialog) return;
    const input = document.getElementById("webhook-secret-value");
    const code = webhookSecretDialog.querySelector("[data-webhook-secret]");
    if (input) input.value = "";
    if (code) code.textContent = "";
  };
  const dismissWebhookSecret = () => {
    if (!webhookSecretDialog) return;
    clearWebhookSecret();
    if (webhookSecretDialog.open) webhookSecretDialog.close();
    window.location.reload();
  };
  webhookSecretDialog?.querySelector("[data-webhook-secret-dismiss]")?.addEventListener("click", dismissWebhookSecret);
  webhookSecretDialog?.addEventListener("cancel", (event) => { event.preventDefault(); dismissWebhookSecret(); });
  window.addEventListener("pagehide", clearWebhookSecret);

  const webhookCreateForm = document.querySelector("[data-webhook-create]");
  const webhookCreateError = document.querySelector("[data-webhook-create-error]");
  webhookCreateForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    const button = webhookCreateForm.querySelector('button[type="submit"]');
    const label = button?.textContent || "Criar";
    if (button) { button.disabled = true; button.textContent = "Enviando…"; }
    if (webhookCreateError) { webhookCreateError.hidden = true; webhookCreateError.textContent = ""; }
    try {
      const response = await fetch(webhookCreateForm.action, {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" },
        body: new URLSearchParams(new FormData(webhookCreateForm)),
      });
      if (response.status === 201) {
        const payload = await response.json();
        const input = document.getElementById("webhook-secret-value");
        const code = webhookSecretDialog?.querySelector("[data-webhook-secret]");
        if (input) input.value = payload.signing_secret || "";
        if (code) code.textContent = payload.signing_secret || "";
        webhookSecretDialog?.showModal();
      } else if (response.status === 400) {
        if (webhookCreateError) { webhookCreateError.textContent = "Integração inválida."; webhookCreateError.hidden = false; }
        else showToast("Integração inválida.");
      } else {
        throw new Error("webhook create failed");
      }
    } catch {
      showToast("Não foi possível criar a integração.");
    } finally {
      if (button) { button.disabled = false; button.textContent = label; }
    }
  });

  const webhookAction = async (form, { confirm, reloadOnSuccess, successToast } = {}) => {
    if (confirm && !(await askConfirm(confirm))) return;
    const button = form.querySelector('button[type="submit"]');
    const label = button?.textContent || "";
    const errorBox = form.querySelector("[data-form-error]");
    if (button) { button.disabled = true; button.textContent = "Enviando…"; }
    if (errorBox) { errorBox.hidden = true; errorBox.textContent = ""; }
    try {
      const response = await fetch(form.action, {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" },
        body: new URLSearchParams(new FormData(form)),
      });
      if (response.status === 204) {
        if (successToast) showToast(successToast);
        if (reloadOnSuccess) window.location.reload();
      } else if (response.status === 400) {
        if (errorBox) { errorBox.textContent = "Integração inválida."; errorBox.hidden = false; }
        else showToast("Integração inválida.");
      } else if (response.status === 404) {
        showToast("Integração não encontrada.");
      } else {
        throw new Error("webhook action failed");
      }
    } catch {
      showToast("Não foi possível concluir a ação.");
    } finally {
      if (button) { button.disabled = false; button.textContent = label; }
    }
  };
  document.querySelectorAll("[data-webhook-edit]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      event.stopPropagation();
      webhookAction(form, { reloadOnSuccess: true });
    });
  });
  document.querySelectorAll("[data-webhook-test]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      event.stopPropagation();
      webhookAction(form, { successToast: "Evento de teste enfileirado." });
    });
  });
  document.querySelectorAll("[data-webhook-delete]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      event.stopPropagation();
      webhookAction(form, { confirm: "Excluir esta integração?", reloadOnSuccess: true });
    });
  });
  // ===== Coverage matrix filtering.
  const coverageFilter = document.getElementById("coverage-filter");
  const coverageRows = Array.from(document.querySelectorAll("[data-coverage-row]"));
  const coverageServiceToggles = Array.from(document.querySelectorAll("[data-coverage-service]"));
  const applyCoverageFilter = () => {
    const filter = coverageFilter?.value || "";
    const checkedServices = coverageServiceToggles.filter((box) => box.checked).map((box) => box.value);
    let visible = 0;
    for (const row of coverageRows) {
      let show;
      if (filter === "none-registered") {
        show = Number(row.dataset.regCount) === 0;
      } else if (filter === "multi-active") {
        show = Number(row.dataset.activeCount) > 1;
      } else if (filter === "missing-registration") {
        // Show when at least one checked service is not registered for this row.
        // No checked services shows all rows.
        show = checkedServices.length === 0 ||
          checkedServices.some((id) => row.getAttribute("data-reg-svc-" + id) === "0");
      } else {
        show = true;
      }
      row.hidden = !show;
      if (show) visible += 1;
    }
    // Service checkboxes only scope the missing-registration mode; hide them
    // otherwise so irrelevant controls are absent while keeping checked state.
    const serviceFieldset = document.querySelector(".coverage-service-filter");
    if (serviceFieldset) serviceFieldset.hidden = filter !== "missing-registration";
    const count = document.getElementById("coverage-count");
    if (count) count.textContent = `Exibindo ${visible} de ${coverageRows.length} contas`;
  };
  coverageFilter?.addEventListener("change", applyCoverageFilter);
  coverageServiceToggles.forEach((box) => box.addEventListener("change", applyCoverageFilter));
  if (coverageFilter) applyCoverageFilter();

})();

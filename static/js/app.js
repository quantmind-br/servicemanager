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

  // ===== Copy: [data-copy-value] copies a fixed string; [data-copy-input] copies
  // the current value of a referenced input. No insecure/deprecated fallback.
  const flashCopyFeedback = (button, message) => {
    const feedback = button.querySelector(".copy-feedback");
    if (!feedback) return;
    feedback.textContent = message;
    window.setTimeout(() => { feedback.textContent = ""; }, 1500);
  };

  const copyText = async (button, text) => {
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      flashCopyFeedback(button, "Não foi possível copiar");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      flashCopyFeedback(button, "Copiado");
    } catch (error) {
      flashCopyFeedback(button, "Não foi possível copiar");
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
      state.controller?.abort();
      secretState.delete(cell);
    }
    const mask = cell.querySelector("[data-secret-mask]");
    if (mask) mask.textContent = "••••••••";
    const showButton = cell.querySelector("[data-secret-show]");
    if (showButton) showButton.textContent = "Exibir";
  };

  const restoreAllMasks = () => {
    for (const cell of Array.from(secretState.keys())) restoreMask(cell);
  };

  const feedbackFor = (cell, message) => {
    const copyButton = cell.querySelector("[data-secret-copy]");
    if (copyButton) flashCopyFeedback(copyButton, message);
  };

  const fetchSecret = async (cell) => {
    const controller = new AbortController();
    const prior = secretState.get(cell);
    if (prior) {
      window.clearTimeout(prior.timer);
      prior.controller?.abort();
    }
    secretState.set(cell, { controller, timer: 0 });
    const response = await fetch(cell.dataset.revealUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error("reveal failed");
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
      try {
        const { controller, value, expiresIn } = await fetchSecret(cell);
        if (controller.signal.aborted || document.hidden) return;
        const mask = cell.querySelector("[data-secret-mask]");
        if (mask) mask.textContent = value;
        button.textContent = "Ocultar";
        const timer = window.setTimeout(() => restoreMask(cell), Math.min(expiresIn, 30) * 1000 || 30000);
        secretState.set(cell, { controller, timer, revealed: true });
      } catch (error) {
        if (error?.name === "AbortError") return;
        restoreMask(cell);
        feedbackFor(cell, "Não foi possível exibir");
      }
    });
  });

  document.querySelectorAll("[data-secret-copy]").forEach((button) => {
    const cell = button.closest("[data-secret-cell]");
    if (!cell) return;
    button.addEventListener("click", async () => {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
        flashCopyFeedback(button, "Não foi possível copiar");
        return;
      }
      try {
        const result = await fetchSecret(cell);
        if (result.controller.signal.aborted) return;
        let value = result.value;
        await navigator.clipboard.writeText(value);
        value = "";
        restoreMask(cell);
        flashCopyFeedback(button, "Copiado");
      } catch (error) {
        if (error?.name === "AbortError") return;
        restoreMask(cell);
        flashCopyFeedback(button, "Não foi possível copiar");
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
        editForm.password.value = "";
        syncCsrfFields(editForm);
        editDialog.showModal();
      });
    });
    editDialog.querySelector("[data-edit-cancel]")?.addEventListener("click", closeEditDialog);
    editDialog.addEventListener("cancel", (event) => { event.preventDefault(); closeEditDialog(); });
    editDialog.addEventListener("click", (event) => {
      if (event.target === editDialog) closeEditDialog();
    });
  }

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  // ===== Fuzzy filter: accent-insensitive, case-insensitive subsequence over
  // each row's data-search (email + status label + non-secret field names/values).
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

  const filterInput = document.getElementById("account-filter");
  const accountsTbody = document.querySelector("table.accounts tbody");
  if (filterInput && accountsTbody) {
    const rowInfo = Array.from(accountsTbody.querySelectorAll("tr[data-row]")).map((tr) => ({
      tr,
      search: normalize(tr.dataset.search || ""),
      detail: document.getElementById("detail-" + tr.dataset.id),
    }));
    const noResults = accountsTbody.querySelector("tr.no-results");
    const applyFilter = () => {
      const query = normalize(filterInput.value.trim());
      let visible = 0;
      for (const info of rowInfo) {
        const show = subsequenceMatch(query, info.search);
        info.tr.hidden = !show;
        if (!show && info.detail) info.detail.hidden = true;
        if (show) visible += 1;
      }
      if (noResults) noResults.hidden = visible !== 0;
    };
    filterInput.addEventListener("input", applyFilter);
    applyFilter();
  }

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

  // ===== Auto-submit: [data-autosubmit] controls POST their form on change.
  document.querySelectorAll("[data-autosubmit]").forEach((control) => {
    control.addEventListener("change", () => {
      const form = control.closest("form");
      if (!form) return;
      if (typeof form.requestSubmit === "function") form.requestSubmit();
      else form.submit();
    });
  });

})();

(() => {
  "use strict";

  const panel = document.querySelector(".reveal-panel");
  const valueOutput = panel?.querySelector(".reveal-value");
  const copyButton = panel?.querySelector(".copy-secret");
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
  let revealedValue = "";
  let clearTimer = 0;
  let activeReveal = null;
  let revealGeneration = 0;

  const clearDisplayedSecret = () => {
    window.clearTimeout(clearTimer);
    clearTimer = 0;
    revealedValue = "";
    if (valueOutput) valueOutput.textContent = "";
    if (panel) panel.hidden = true;
  };

  const discardReveal = () => {
    revealGeneration += 1;
    activeReveal?.abort();
    activeReveal = null;
    clearDisplayedSecret();
  };

  const showSecret = (value, expiresIn) => {
    clearDisplayedSecret();
    revealedValue = value;
    if (valueOutput) valueOutput.textContent = revealedValue;
    if (panel) panel.hidden = false;
    clearTimer = window.setTimeout(clearDisplayedSecret, Math.min(expiresIn, 30) * 1000 || 30000);
  };

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) discardReveal();
  });
  window.addEventListener("pagehide", discardReveal);

  document.querySelectorAll("[data-reveal-url]").forEach((button) => {
    button.addEventListener("click", async () => {
      discardReveal();
      const generation = revealGeneration;
      const controller = new AbortController();
      activeReveal = controller;
      try {
        const response = await fetch(button.dataset.revealUrl, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" },
          signal: controller.signal,
        });
        if (!response.ok) {
          if (!controller.signal.aborted && !document.hidden && generation === revealGeneration) window.location.assign("/reauth");
          return;
        }
        const payload = await response.json();
        if (!controller.signal.aborted && !document.hidden && generation === revealGeneration) showSecret(payload.value, payload.expires_in);
        payload.value = "";
      } catch (error) {
        if (error?.name !== "AbortError" && !document.hidden && generation === revealGeneration) window.location.assign("/reauth");
      } finally {
        if (activeReveal === controller) activeReveal = null;
      }
    });
  });

  copyButton?.addEventListener("click", async () => {
    if (!revealedValue || document.hidden || !navigator.clipboard) return;
    await navigator.clipboard.writeText(revealedValue);
  });

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

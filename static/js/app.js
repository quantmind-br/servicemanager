(() => {
  "use strict";

  const panel = document.querySelector(".reveal-panel");
  const valueOutput = panel?.querySelector(".reveal-value");
  const copyButton = panel?.querySelector(".copy-secret");
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
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

  const bootstrap = document.querySelector("[data-bootstrap-enrollment]");
  if (bootstrap instanceof HTMLElement) {
    const form = bootstrap.querySelector("form");
    const issueButton = bootstrap.querySelector(".issue-totp");
    const enrollment = bootstrap.querySelector("#totp-enrollment");
    const secretOutput = bootstrap.querySelector(".totp-secret");
    const accountOutput = bootstrap.querySelector(".totp-account");
    const qrImage = bootstrap.querySelector(".totp-qr");
    const bootstrapError = bootstrap.querySelector(".bootstrap-error");
    const recoveryCodes = bootstrap.querySelector("#recovery-codes");
    const recoveryCodeList = bootstrap.querySelector(".recovery-code-list");
    const showBootstrapError = (message) => {
      if (bootstrapError) {
        bootstrapError.textContent = message;
        bootstrapError.hidden = false;
      }
    };
    const clearBootstrapError = () => {
      if (bootstrapError) {
        bootstrapError.textContent = "";
        bootstrapError.hidden = true;
      }
    };
    const clearEnrollment = () => {
      if (secretOutput) secretOutput.textContent = "";
      if (accountOutput) accountOutput.textContent = "";
      if (qrImage instanceof HTMLImageElement) {
        qrImage.removeAttribute("src");
        qrImage.hidden = true;
      }
      if (enrollment) enrollment.hidden = true;
    };
    issueButton?.addEventListener("click", async () => {
      if (!(form instanceof HTMLFormElement) || !(issueButton instanceof HTMLButtonElement)) return;
      issueButton.disabled = true;
      clearBootstrapError();
      try {
        const response = await fetch(bootstrap.dataset.bootstrapIssueUrl, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" },
          body: new FormData(form),
        });
        if (!response.ok) throw new Error("bootstrap enrollment failed");
        const payload = await response.json();
        const totpSecret = payload.totp_secret;
        const qrSvg = payload.qr_svg_base64;
        if (typeof totpSecret !== "string" || !totpSecret || typeof qrSvg !== "string" || !qrSvg) throw new Error("invalid enrollment response");
        if (secretOutput) secretOutput.textContent = totpSecret;
        if (accountOutput) accountOutput.textContent = "Service Manager";
        if (qrImage instanceof HTMLImageElement) {
          qrImage.src = `data:image/svg+xml;base64,${qrSvg}`;
          qrImage.hidden = false;
        }
        if (enrollment) enrollment.hidden = false;
        payload.totp_secret = "";
        payload.qr_svg_base64 = "";
      } catch (_) {
        issueButton.disabled = false;
        showBootstrapError("Não foi possível gerar o código do autenticador.");
      }
    });
    if (form instanceof HTMLFormElement) form.addEventListener("submit", async (event) => {
      event.preventDefault();
      clearBootstrapError();
      const submitButton = form.querySelector('button[type="submit"]');
      if (submitButton instanceof HTMLButtonElement) submitButton.disabled = true;
      try {
        const response = await fetch(form.action, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" },
          body: new FormData(form),
        });
        if (response.status === 400) {
          showBootstrapError("Não foi possível confirmar a ativação. Verifique os dados e tente novamente.");
          return;
        }
        if (!response.ok) throw new Error("bootstrap confirmation failed");
        const payload = await response.json();
        if (!Array.isArray(payload.recovery_codes) || payload.recovery_codes.length !== 10) throw new Error("invalid recovery response");
        if (recoveryCodeList) recoveryCodeList.textContent = payload.recovery_codes.join("\n");
        if (recoveryCodes) recoveryCodes.hidden = false;
        payload.recovery_codes.fill("");
        clearEnrollment();
        form.reset();
        form.querySelectorAll("input, button, select, textarea").forEach((element) => { element.disabled = true; });
      } catch (_) {
        showBootstrapError("Não foi possível confirmar a ativação. Tente novamente.");
      } finally {
        if (submitButton instanceof HTMLButtonElement && !(recoveryCodes && !recoveryCodes.hidden)) submitButton.disabled = false;
      }
    });
  }
})();

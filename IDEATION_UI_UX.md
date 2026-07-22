# UI/UX Improvements Analysis Report

Scope: Flask + Jinja server-rendered app (`templates/`), one stylesheet (`static/css/app.css`), one script (`static/js/app.js`), route layer (`service_manager/routes.py`, `service_manager/auth.py`). Dark credential-vault theme, pt-BR UI, no framework.

## Executive Summary

The frontend is already well-polished from a prior UI/UX pass (see `tests/test_uiux.py`): styled auth failures, `?ok=` success feedback, mobile card layout, 44px coarse-pointer touch targets, `prefers-reduced-motion`, native `<dialog>` confirms, optimistic fetch updates with rollback, per-cell secret reveal with expiry warning.

The remaining gaps cluster in three areas:

1. **Unstyled dead-end error responses** — 8 mutation routes return raw `Response("…", 400)` plain-text bodies, dropping the user out of the app with no navigation and losing all typed input. This is the single largest UX defect left.
2. **Inconsistent async-failure surfacing** — session expiry during a reveal shows a generic 1.5s micro-tooltip instead of redirecting to login; rate-limit errors are announced in a tiny transient label instead of the existing toast.
3. **State loss on full-page form actions** — saving/adding/deleting a custom field reloads the page and collapses the expanded detail row, resets filters, and loses scroll position.

**14 issues found: 3 high, 6 medium, 5 low.**

## Issues Found

### High Priority

#### UIUX-001: Validation errors return unstyled plain-text pages and destroy form input

**Category:** usability

**Affected Components:**
- `service_manager/routes.py` (lines 235, 250, 335, 348, 360, 374, 397, 435–437, 462)
- `templates/index.html` (add-account panel, edit dialog, service-add form, field forms)

**Current State:**
Duplicate email on "Adicionar conta" or the edit dialog, an invalid field value, or an invalid service name returns `Response("Email já cadastrado", status=400)` — a bare white-on-white plain-text body with no header, no styles, no back link. Everything the user typed is gone. The styled `400.html` template only fires for `abort(400)`, not these explicit `Response` objects. Note the app *already has* the right pattern for imports: `import_bulk` redirects back with `?error=<kind>` rendered into the `data-feedback` banner (routes.py:284–297, 205–212).

**Proposed Change:**
Replace every user-triggerable `Response("…", 400)` in form routes with the existing import-error pattern: `redirect(url_for("routes.index", service=service_id, error="duplicate_email"))` (extend the `error_messages` dict at routes.py:206) and render the message through the existing `.feedback` banner with an error variant class (`feedback-error` already exists in CSS). Keep 400s only for non-browser/malformed requests (missing CSRF, tampered ids).

**User Benefit:**
Validation failure keeps the user inside the app with a styled, dismissible message instead of a dead-end page; the most common failure (duplicate email) becomes recoverable.

**Code Example:**
```python
# Current (routes.py:248-251)
except Exception as error:
    if "UNIQUE" in str(error).upper():
        return Response("Email já cadastrado", status=400)
    raise

# Proposed
ERROR_MESSAGES = {..., "duplicate_email": "Email já cadastrado."}
except Exception as error:
    if "UNIQUE" in str(error).upper():
        return redirect(url_for("routes.index", service=service_id, error="duplicate_email"))
    raise
```
```html
<!-- index.html:12 — reuse the error styling on the banner when error param present -->
<p class="feedback{% if feedback_is_error %} feedback-error{% endif %}" role="{{ 'alert' if feedback_is_error else 'status' }}" data-feedback>{{ feedback }}</p>
```

**Estimated Effort:** small

---

#### UIUX-002: Session expiry during password reveal shows a misleading generic error

**Category:** usability

**Affected Components:**
- `static/js/app.js` (`fetchSecret`, lines 88–96; error handlers at 117–120, 145–149)

**Current State:**
When the session expires and the user clicks "Exibir", the reveal POST is redirected to `/login`, which returns 200 HTML. `response.ok` passes, `response.json()` throws, and the catch shows "Não foi possível exibir" in a 1.5s micro-tooltip. The user retries forever with no clue they're logged out. The autosubmit path already solves this correctly (app.js:362–365: detects `response.redirected` → `/login` → `window.location.assign`).

**Proposed Change:**
Apply the same redirect check inside `fetchSecret` before `response.ok`:

**Code Example:**
```js
// Proposed — in fetchSecret, after the fetch:
if (response.redirected && new URL(response.url).pathname === "/login") {
  window.location.assign(response.url);
  return new Promise(() => {}); // navigation in flight
}
if (!response.ok) { ... }
```

**User Benefit:**
Expired sessions route the user straight to login instead of a silently failing button.

**Estimated Effort:** trivial

---

#### UIUX-003: Reveal/copy failures announced in a 1.5-second micro-tooltip instead of the toast

**Category:** usability

**Affected Components:**
- `static/js/app.js` (`feedbackFor` line 74–77, reveal error handler 117–120, secret-copy handler 145–149; `showToast` 325–331)

**Current State:**
"Limite de revelações atingido" (429) and "Não foi possível exibir" are flashed through `flashCopyFeedback` — a `.68rem` absolutely-positioned label that disappears after 1500ms. A rate-limit lockout is a blocking condition; users routinely miss the message and keep clicking. Meanwhile a proper toast component (`#toast`, `role="alert"`, 5s duration) exists and is used for autosubmit failures.

**Proposed Change:**
Route error-class messages (429, reveal failure, clipboard-unavailable) through `showToast(...)`; keep `flashCopyFeedback` only for the "Copiado" success micro-confirmation. In the reveal handler:

```js
// Current
feedbackFor(cell, error?.status === 429 ? "Limite de revelações atingido" : "Não foi possível exibir");
// Proposed
showToast(error?.status === 429 ? "Limite de revelações atingido. Aguarde alguns minutos." : "Não foi possível exibir a senha.");
```
(Requires hoisting `showToast` above the reveal block or defining it earlier — it is currently declared at line 325, after the handlers.)

**User Benefit:**
Blocking errors get 5 seconds of legible, screen-reader-announced visibility instead of a subliminal flash.

**Estimated Effort:** trivial

---

### Medium Priority

#### UIUX-004: Password inputs in "Adicionar conta" and the edit dialog lack the visibility toggle

**Category:** usability / consistency

**Affected Components:**
- `templates/index.html` (line 73 add-account password; line 235 edit-dialog password)
- `templates/login.html`, `account.html`, `reauth.html` (already have it)

**Current State:**
Every auth-page password input ships a `.password-field` wrapper with the eye toggle (`data-password-toggle`, `aria-pressed`). The two places where users *type new secrets they must get right* — adding an account and editing one — render a bare `type="password"` input. Typing a 40-char generated password blind into the vault is exactly where a reveal toggle matters most. The JS already binds any `[data-password-toggle]` (app.js:396–405); this is template-only work.

**Proposed Change:**
Wrap both inputs in the existing `.password-field` + toggle markup used in `login.html:12–15`. Extract the repeated toggle markup into a Jinja macro (it is currently copy-pasted 5×) in `base.html` or a `_macros.html`.

**User Benefit:**
Users can verify a pasted/typed credential before committing it; removes a jarring inconsistency.

**Estimated Effort:** small

---

#### UIUX-005: Dialogs have no accessible name

**Category:** accessibility

**Affected Components:**
- `templates/index.html` (`#account-edit-dialog` line 228, `#confirm-dialog` line 243)

**Current State:**
`#account-edit-dialog` contains an `<h3>Editar conta</h3>` but the dialog is not associated with it; `#confirm-dialog` has only a `<p>`. Screen readers announce both as unnamed dialogs on `showModal()`.

**Proposed Change:**
```html
<dialog id="account-edit-dialog" class="account-edit-dialog" aria-labelledby="edit-dialog-title">
  ... <h3 id="edit-dialog-title">Editar conta</h3> ...
<dialog id="confirm-dialog" class="account-edit-dialog" aria-labelledby="confirm-dialog-message">
  <p id="confirm-dialog-message" data-confirm-message></p>
```

**User Benefit:**
Screen-reader users hear "Editar conta, diálogo" / the confirmation question immediately on open.

**Estimated Effort:** trivial

---

#### UIUX-006: Custom-field save/add/delete collapses the expanded row and resets filters

**Category:** interaction / state handling

**Affected Components:**
- `templates/index.html` (field forms, lines 181–214)
- `static/js/app.js` (expansion handler 310–320, filter block 261–307)
- `service_manager/routes.py` (`field_update`/`field_add`/`field_delete` redirects, lines 452, 473, 487)

**Current State:**
Editing a field value lives inside an expanded detail row. Submitting "Salvar" does a full POST → redirect → reload: the detail row re-renders collapsed, active filters clear, and scroll position resets. Editing three fields on one account means re-expanding and re-scrolling three times. Status/registered updates already avoid this via `data-fetch-update`.

**Proposed Change:**
Cheapest robust fix (no fetch conversion): include the row anchor in the redirect and auto-expand on load.
1. Redirect to `url_for("routes.index", service=service_id, ok="field_saved") + f"#row-{account_id}"` (row ids `row-{{ id }}` already exist, index.html:113).
2. In `app.js`, on load: if `location.hash` matches `#row-<id>`, trigger the row's `[data-expand]` button and `scrollIntoView({ block: "center" })`.
Alternative (bigger): convert the field-value form to the existing `data-fetch-update` path with toast feedback.

**User Benefit:**
Editing account details stops feeling like starting over after every save.

**Estimated Effort:** small (anchor approach) / medium (fetch conversion)

---

#### UIUX-007: Import result banner re-appears on refresh; `added`/`skipped`/`error` params never stripped

**Category:** state handling

**Affected Components:**
- `static/js/app.js` (feedback block, lines 408–416)
- `service_manager/routes.py` (lines 204–221)

**Current State:**
The auto-dismiss + `history.replaceState` cleanup only handles `?ok=`. Import outcomes redirect with `?added=&skipped=` or `?error=` — those survive in the URL, so refreshing or bookmarking re-shows "Importação concluída: 20 adicionadas…" indefinitely, and the banner never auto-dismisses.

**Proposed Change:**
```js
// app.js:410-415 — strip all feedback params
const params = ["ok", "added", "skipped", "error"];
if (params.some((p) => url.searchParams.has(p))) {
  const isError = url.searchParams.has("error");
  params.forEach((p) => url.searchParams.delete(p));
  window.history.replaceState(null, "", url);
  if (!isError) window.setTimeout(() => { feedbackBanner.hidden = true; }, 6000);
}
```
Keep error banners persistent (no timeout) — errors should be dismissed by the user, not the clock.

**User Benefit:**
Stale success messages stop haunting reloads; error messages persist until read.

**Estimated Effort:** trivial

---

#### UIUX-008: Current service chip not announced; silent saves for assistive tech

**Category:** accessibility

**Affected Components:**
- `templates/index.html` (chip nav, line 18; autosubmit forms 131–153)
- `static/js/app.js` (autosubmit success path, 367–384)

**Current State:**
1. The selected service chip is only distinguished by the `is-current` background — no `aria-current="page"`, so screen-reader users cannot tell which vault is active.
2. Successful status/registered fetch-saves are announced only visually (pill recolor / toggle slide). No `aria-live` confirmation exists; failures get the toast but successes are silent.

**Proposed Change:**
```html
<a class="chip{% if service['id'] == current %} is-current{% endif %}"
   {% if service['id'] == current %}aria-current="page"{% endif %} href="...">
```
Add a visually hidden live region (`<span id="save-announcer" class="sr-only" aria-live="polite">`) and set it to "Status salvo." / "Cadastro salvo." in the autosubmit success branch.

**User Benefit:**
Non-visual users get parity: current context and save confirmations.

**Estimated Effort:** trivial

---

#### UIUX-009: Copy-confirmation tooltip clipped by the table scroll container

**Category:** visual

**Affected Components:**
- `static/css/app.css` (`.copy-feedback` 368–379, `.table-wrap` 317)

**Current State:**
`.table-wrap { overflow-x: auto; }` also clips vertical overflow (computed `overflow-y: auto`). `.table-wrap .copy-feedback` is repositioned *below* the button (`top: calc(100% + .2rem)`), so for the **last row** of the table the "Copiado" label renders outside the scroll container and is cut off — the one confirmation users watch for after copying a password. [INFERENCE from CSS overflow semantics; verify with one last-row copy click.]

**Proposed Change:**
Stop using absolute positioning for the confirmation inside tables. Simplest fix matching current design: swap the copy icon for a checkmark + accent color on the button itself for 1.5s (no layout escape needed):
```js
// flashCopyFeedback fallback when tooltip would clip:
button.classList.add("is-copied");           // CSS: .copy-button.is-copied { color: var(--green); border-color: var(--green-border); }
setTimeout(() => button.classList.remove("is-copied"), 1500);
```
Keep the `aria-live` text update for screen readers.

**User Benefit:**
Copy feedback is always visible, including the row users most recently scrolled to.

**Estimated Effort:** small

---

### Low Priority

#### UIUX-010: No skip-to-content link

**Category:** accessibility

**Affected Components:** `templates/base.html`

**Current State:** Keyboard users tab through brand + header actions on every page before reaching content. Header is small (4 stops), so impact is limited — hence low.

**Proposed Change:**
```html
<body>
  <a class="skip-link" href="#main">Ir para o conteúdo</a>
  ...
  <main id="main" class="page-shell">
```
```css
.skip-link { position: absolute; left: -9999px; }
.skip-link:focus { left: 1rem; top: 1rem; z-index: 30; background: var(--bg-elev-2); padding: .5rem .9rem; border-radius: var(--radius-sm); }
```

**Estimated Effort:** trivial

---

#### UIUX-011: "Exibir" button gives no in-flight indication

**Category:** performance perception

**Affected Components:** `static/js/app.js` (reveal handler 102–124)

**Current State:** During the reveal POST the button is `disabled` (opacity .55) but keeps saying "Exibir". On a slow link this reads as a dead click.

**Proposed Change:** Set `button.textContent = "…"` (or add a `.is-loading` class with a CSS spinner) after `button.disabled = true`, restore in `finally`. Matches the existing "Enviando…" submit-lock convention (app.js:236).

**Estimated Effort:** trivial

---

#### UIUX-012: Toast is hardcoded as an error component

**Category:** visual / consistency

**Affected Components:** `static/css/app.css` (`.toast` 564–577), `static/js/app.js` (`showToast`)

**Current State:** `.toast` is styled red-bordered/red-text. UIUX-003 and UIUX-006 will start routing non-error messages through it.

**Proposed Change:** Make the base `.toast` neutral (`color: var(--ink)`, `border-color: var(--border-strong)`), add `.toast-error` (current red styling) and optionally `.toast-success` (green tokens already exist). `showToast(message, kind = "error")` applies the class.

**Estimated Effort:** trivial

---

#### UIUX-013: Edit dialog fields always stack single-column

**Category:** visual

**Affected Components:** `static/css/app.css` (`.detail-grid` 487)

**Current State:** `.detail-grid { grid-template-columns: 1fr; }` unconditionally; on desktop the dialog wastes width and forces extra vertical scanning.

**Proposed Change:**
```css
@media (min-width: 34rem) {
  .account-edit-dialog .detail-grid { grid-template-columns: 1fr 1fr; }
}
```

**Estimated Effort:** trivial

---

#### UIUX-014: No user-controlled column sorting in the accounts table

**Category:** usability

**Affected Components:** `templates/index.html` (thead 100–108), `service_manager/routes.py` (fixed sort, line 199)

**Current State:** Rows are always status-then-email (routes.py:199). With ~116 accounts, finding "most recently touched" or sorting purely by email requires the filter box. Client-side sort is cheap since all rows are already in the DOM.

**Proposed Change:** Make "Email" and "Status" `<th>` clickable buttons that re-append `tr[data-row]` (+ their paired `detail-` rows) in sorted order, toggling `aria-sort="ascending|descending"` on the active header. Pure JS, no server change; reuse `data-search`/`data-status` attributes already present.

**Estimated Effort:** medium

---

## Summary

| Category | Count |
|----------|-------|
| Usability | 5 (UIUX-001, 002, 003, 004, 014) |
| Accessibility | 3 (UIUX-005, 008, 010) |
| Performance Perception | 1 (UIUX-011) |
| Visual Polish | 3 (UIUX-009, 012, 013) |
| Interaction / State Handling | 2 (UIUX-006, 007) |

**Total Components Analyzed:** 15 (11 templates, `app.js`, `app.css`, `routes.py`, `auth.py`)
**Total Issues Found:** 14 (3 high · 6 medium · 5 low)

### Strengths worth preserving (do not regress)

- Per-cell secret state with abort + expiry warning (`is-expiring`), masks restored on tab hide/pagehide
- Optimistic autosubmit with rollback + login-redirect detection (extend, don't replace — see UIUX-002)
- Mobile card layout with `data-label` headers, 44px coarse-pointer targets, `prefers-reduced-motion`
- `noscript` fallbacks on every autosubmit form; CSRF re-sync on `pageshow`
- Contract tests in `tests/test_uiux.py` pin these invariants — extend them for any fix above

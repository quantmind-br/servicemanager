# UI/UX Improvements Analysis Report

Scope: server-rendered Flask/Jinja app, Brazilian-Portuguese UI, no-framework JS/CSS, strict CSP.
Analyzed: 13 templates (`templates/`), `static/css/app.css` (~1000 lines), `static/js/app.js` (817 lines).

## Executive Summary

The UI baseline is unusually solid for a no-framework app: skip link, `:focus-visible` styles, `aria-live` announcers, `prefers-reduced-motion` support, 44px coarse-pointer touch targets, `<noscript>` fallbacks, per-row loading states on secret reveal, and consistent empty states. The issues found are therefore concentrated in the gaps: the mobile stacked-table mode silently drops sorting and select-all, the coverage matrix is legible only through `title` tooltips and an unexplained letter code, the sticky header overflows on narrow admin screens, and a few dynamic-update paths lose keyboard focus or misuse `role="alert"`.

**18 issues found: 5 high, 8 medium, 5 low.**

---

## Issues Found

### High Priority

#### UIUX-001: Admin header overflows horizontally on mobile

**Category:** usability / visual

**Affected Components:**
- `templates/base.html` (lines 14–31)
- `static/css/app.css` (`.site-header`, lines 84–95; `.header-actions`, line 98)

**Current State:**
`.site-header` is `display: flex; justify-content: space-between` with no `flex-wrap`. For an admin the header holds the brand + user label + 5 actions (Usuários, Auditoria, Visão geral, Minha conta, Sair). Below ~600px these overflow the viewport; only `.header-user` is hidden (`@media (max-width: 30rem)`). The sticky header then forces horizontal page scroll.

**Proposed Change:**
Allow wrapping and compact the nav on small screens:

```css
/* app.css */
.site-header { flex-wrap: wrap; row-gap: .25rem; padding-block: .4rem; }
@media (max-width: 48rem) {
  .header-actions { flex-wrap: wrap; justify-content: flex-end; row-gap: .3rem; }
  .header-actions .button-quiet { font-size: .78rem; padding: .3rem .5rem; }
}
```

Optionally collapse admin-only links behind a `<details class="header-menu">` on `max-width: 30rem`.

**User Benefit:** Admins on phones can reach Auditoria/Usuários without horizontal scrolling under a sticky header.

**Estimated Effort:** small

---

#### UIUX-002: Mobile stacked table drops sorting and select-all

**Category:** usability

**Affected Components:**
- `static/css/app.css` (line 650: `table.accounts thead { display: none; }`)
- `templates/index.html` (thead, lines 112–121)

**Current State:**
The responsive stacked layout (`@media (max-width: 48rem)`) hides the entire `<thead>`. That removes: the “Selecionar contas visíveis” master checkbox (`#select-visible`) and both sort buttons (`.th-sort`). Bulk selection on mobile degrades to tapping each row checkbox one by one; sorting becomes impossible even though `?sort=`/`?dir=` deep links exist (`app.js` lines 442–449) — a shared sorted link opens unsorted-looking on mobile only after reload quirks.

**Proposed Change:**
Add a mobile-only control strip that reuses the existing JS handlers instead of resurrecting the thead:

```html
<!-- index.html, inside .table-controls, visible only under 48rem -->
<div class="mobile-table-tools">
  <label class="checkbox-label"><input type="checkbox" id="select-visible-mobile"> Selecionar visíveis</label>
  <label class="filter-select">Ordenar
    <select id="mobile-sort">
      <option value="">Padrão</option>
      <option value="email:asc">Email A→Z</option>
      <option value="email:desc">Email Z→A</option>
      <option value="status:asc">Status</option>
    </select>
  </label>
</div>
```

In `app.js`, proxy `#select-visible-mobile` to the same handler as `#select-visible`, and map `#mobile-sort` changes to the existing `.th-sort` click logic. Hide `.mobile-table-tools` above 48rem, show below.

**User Benefit:** Feature parity on phones for the two most common table operations (bulk select, sort).

**Estimated Effort:** medium

---

#### UIUX-003: Coverage matrix is unreadable without hover — no legend, `title`-only semantics

**Category:** accessibility / usability

**Affected Components:**
- `templates/coverage.html` (lines 32–36)
- `static/css/app.css` (`.cov*`, lines 546–552)

**Current State:**
Cells render `A` / `I` / `·` / `—` colored by status, with a 5px accent dot for “cadastrada” (`.cov-reg::after`). All meaning lives in the `title` attribute — invisible on touch devices, unreliable for screen readers, and there is no legend anywhere explaining the letter code or the corner dot. The `·` (sem uso) glyph is also a near-invisible target label.

**Proposed Change:**
1. Add a legend above the table:

```html
<div class="coverage-legend muted" aria-hidden="false">
  <span class="cov cov-ativo">A</span> Ativa ·
  <span class="cov cov-inativo">I</span> Inativa ·
  <span class="cov cov-nunca">·</span> Sem uso ·
  <span class="cov cov-missing">—</span> Sem vínculo ·
  <span class="cov cov-ativo cov-reg">A</span> ponto azul = cadastrada
</div>
```

2. Make cell semantics real text, not tooltip:

```html
<a href="…" class="cov cov-{{ cell['status'] }}…">
  {{ 'A' if … }}<span class="sr-only">{{ service['name'] }}: {{ labels[cell['status']] }}{{ ', cadastrada' if cell['registered'] }}</span>
</a>
```

(keep `title` for mouse users).

**User Benefit:** Matrix becomes self-explanatory; screen-reader and touch users get the same information mouse users get from tooltips.

**Estimated Effort:** small

---

#### UIUX-004: Auto-submit controls lose keyboard focus when disabled mid-flight

**Category:** accessibility

**Affected Components:**
- `static/js/app.js` (lines 576/615 `control.disabled = true/false`; same pattern at 703, 729 for admin controls)

**Current State:**
On status/cadastro change the control is `disabled` during the fetch. Disabling the currently-focused element moves focus to `<body>`; when re-enabled, focus is NOT restored. A keyboard or screen-reader user changing several statuses must re-Tab from the top of the table after every change.

**Proposed Change:**
Use `aria-busy` + re-focus instead of relying on `disabled` alone:

```js
// app.js, in the [data-autosubmit] handler
const hadFocus = document.activeElement === control;
control.disabled = true;
try { … } finally {
  control.disabled = false;
  if (hadFocus) control.focus();
}
```

Apply the same pattern to `[data-admin-role]` and `[data-admin-active]`.

**User Benefit:** Keyboard/AT users keep their place in the table while making sequential edits — the main workflow of this app.

**Estimated Effort:** trivial

---

#### UIUX-005: Success toasts use `role="alert"` (assertive) and one shared live region

**Category:** accessibility

**Affected Components:**
- `static/js/app.js` (`showToast`, lines 30–37)
- `templates/index.html` line 265, `templates/admin_users.html` line 66 (`<div id="toast" role="alert">`)

**Current State:**
`showToast("Link copiado.", "success")` (line 455) and other non-error messages fire through a `role="alert"` region, interrupting screen-reader output for benign confirmations. Errors and successes share the exact same element, so the role can't differ.

**Proposed Change:**
Set the role dynamically in `showToast`:

```js
const showToast = (message, kind = "error") => {
  toast.setAttribute("role", kind === "error" ? "alert" : "status");
  toast.textContent = message;
  toast.className = kind === "error" ? "toast toast-error" : "toast";
  …
};
```

Remove the hardcoded `role="alert"` from the templates (JS sets it before showing).

**User Benefit:** Screen readers announce successes politely and reserve interruptions for real errors.

**Estimated Effort:** trivial

---

### Medium Priority

#### UIUX-006: Audit table — missing `scope`, raw ISO timestamps, raw JSON metadata, tooltip-only truncation

**Category:** accessibility / usability

**Affected Components:**
- `templates/audit.html` (lines 26, 31, 35)

**Current State:**
1. `<th>ID</th>…` have no `scope="col"` (index/admin tables have it — inconsistent).
2. `occurred_at` renders as raw ISO/DB string.
3. `metadata_json` renders raw JSON, truncated by CSS with the full value only in `title` (invisible on touch).

**Proposed Change:**

```html
<th scope="col">ID</th> <!-- all 7 headers -->
<td><time datetime="{{ event['occurred_at'] }}">{{ event['occurred_at'] | format_dt }}</time></td>
<td class="audit-metadata"><details><summary>{{ (event['metadata_json'] or '{}') | truncate(48) }}</summary><pre>{{ event['metadata_json'] | pretty_json }}</pre></details></td>
```

Add small Jinja filters `format_dt` (dd/mm/aaaa hh:mm) and `pretty_json` in `app.py`.

**User Benefit:** Auditors can actually read event details on any device; dates are scannable.

**Estimated Effort:** small

---

#### UIUX-007: Header nav has no current-page indicator

**Category:** usability / accessibility

**Affected Components:**
- `templates/base.html` (lines 20–24)

**Current State:**
The four nav links (`Usuários`, `Auditoria`, `Visão geral`, `Minha conta`) look identical regardless of which page is open. The service chips already implement the correct pattern (`aria-current="page"` + `.is-current`).

**Proposed Change:**

```html
<a class="button button-quiet{% if request.endpoint == 'routes.coverage' %} is-active{% endif %}"
   {% if request.endpoint == 'routes.coverage' %}aria-current="page"{% endif %} …>Visão geral</a>
```

```css
.site-header .button-quiet[aria-current="page"] { border-color: var(--accent); color: var(--accent); }
```

**User Benefit:** Orientation — users always know which section they're in; matches the chip pattern already in the app.

**Estimated Effort:** trivial

---

#### UIUX-008: Bulk bar appearing/disappearing causes layout shift and can scroll out of view

**Category:** performance perception / usability

**Affected Components:**
- `templates/index.html` (line 97), `static/css/app.css` (`.bulk-bar`, lines 563–567)

**Current State:**
`#bulk-bar` is unhidden above the table when the first row is checked, pushing the whole table down (layout shift right under the user's pointer). When selecting rows deep in a long table, the bar is off-screen — user checks 30 rows and sees no affordance to act on them.

**Proposed Change:**

```css
.bulk-bar { position: sticky; top: 3.75rem; /* below sticky header */ z-index: 9; }
```

Sticky positioning keeps the reserved DOM position (shift happens once) and keeps actions visible while scrolling the selection.

**User Benefit:** Bulk actions stay reachable during long selections; less content jumping.

**Estimated Effort:** trivial

---

#### UIUX-009: Bulk action buttons allow double-submit

**Category:** usability

**Affected Components:**
- `static/js/app.js` (`submitBulk`, lines 499–528)

**Current State:**
`submitBulk` builds a form and calls `form.submit()`, which does **not** fire the `submit` event — so the global double-submit lock (lines 250–272) never engages. Double-clicking “Excluir selecionadas” can POST twice.

**Proposed Change:**

```js
let bulkSubmitting = false;
const submitBulk = (action, extra = {}) => {
  if (bulkSubmitting || !selectedAccountIds.size) return;
  bulkSubmitting = true;
  document.querySelectorAll("#bulk-bar button").forEach((b) => { b.disabled = true; });
  …
  form.submit();
};
```

**User Benefit:** No duplicate bulk mutations/audit events from an impatient double click.

**Estimated Effort:** trivial

---

#### UIUX-010: Password minimum length (16) is not communicated before validation failure

**Category:** usability (form UX)

**Affected Components:**
- `templates/account.html` (line 26)
- `templates/_macros.html`

**Current State:**
`password_field("new_password", "new-password", minlength=16)` enforces 16 chars, but the only feedback is the browser's native validation bubble after the user has already typed and submitted a shorter password.

**Proposed Change:**

```html
<label>Nova senha <span class="muted-hint">(mínimo 16 caracteres)</span>
  {{ password_field("new_password", "new-password", minlength=16) }}
</label>
```

Optionally wire `aria-describedby` from the input to the hint by letting the macro accept a `hint_id`.

**User Benefit:** Users compose a valid password on the first attempt instead of discovering the rule by failing.

**Estimated Effort:** trivial

---

#### UIUX-011: Coverage page has no text filter for accounts

**Category:** usability

**Affected Components:**
- `templates/coverage.html` (lines 10–19), `static/js/app.js` (lines 797–814)

**Current State:**
The matrix offers only two canned filters (“Não cadastrada em nenhum serviço”, “Ativa em mais de um serviço”). With dozens of accounts there is no way to jump to one email — unlike the main table, which has the fuzzy `#account-filter`.

**Proposed Change:**
Add a search input and AND it into `applyCoverageFilter` (the row email is already in the first `<th scope="row">`):

```html
<label class="filter-field"><span class="sr-only">Filtrar contas</span>
  <input id="coverage-search" type="search" placeholder="Filtrar contas…" autocomplete="off"></label>
```

```js
const q = normalize(coverageSearch?.value || "");
const show = (!q || normalize(row.querySelector(".coverage-email").textContent).includes(q)) && (existing filter…);
```

Reuse the existing `normalize()` helper for accent-insensitive matching.

**User Benefit:** Consistency with the accounts table; direct lookup in large matrices.

**Estimated Effort:** small

---

#### UIUX-012: Feedback banner auto-hide collapses the page heading (layout shift)

**Category:** performance perception / visual

**Affected Components:**
- `static/js/app.js` (lines 632–642), `templates/index.html` (line 13)

**Current State:**
Success feedback (`data-feedback`) is set `hidden = true` after 6s, abruptly removing the element and shifting everything below it — potentially mid-click on the table.

**Proposed Change:**
Fade + reserve space instead of removing:

```css
.feedback { transition: opacity .3s ease; }
.feedback.is-dismissed { opacity: 0; visibility: hidden; }
```

```js
if (!isError) window.setTimeout(() => { feedbackBanner.classList.add("is-dismissed"); }, 6000);
```

(`visibility: hidden` keeps AT from re-reading it; the box keeps its height so nothing jumps. The `prefers-reduced-motion` block already zeroes the transition.)

**User Benefit:** No content jump under the cursor seconds after page load.

**Estimated Effort:** trivial

---

#### UIUX-013: Audit pagination lacks context and “Anterior/Próxima” shift position

**Category:** usability

**Affected Components:**
- `templates/audit.html` (lines 44–47)

**Current State:**
Pagination shows only the buttons that apply; on page 1 “Próxima” sits where “Anterior” will later appear, so the buttons move between pages. Page count/total events are never shown (“Página 2” appears only inside the panel heading).

**Proposed Change:**

```html
<nav class="pagination" aria-label="Paginação da auditoria">
  <a class="button button-quiet{% if page <= 1 %} is-disabled{% endif %}" …>Anterior</a>
  <span class="muted">Página {{ page }}</span>
  <a class="button button-quiet{% if not has_next %} is-disabled{% endif %}" …>Próxima</a>
</nav>
```

```css
.pagination .is-disabled { opacity: .45; pointer-events: none; }
```

**User Benefit:** Stable click targets and visible position while paging through events.

**Estimated Effort:** trivial

---

### Low Priority

#### UIUX-014: Buttons have hover but no `:active` (pressed) state

**Category:** visual / interaction

**Affected Components:**
- `static/css/app.css` (`.button`, `.chip`, `.copy-button`)

**Current State:**
Hover states are thorough, but nothing acknowledges the press itself; on touch (no hover) taps give zero visual response beyond navigation latency.

**Proposed Change:**

```css
.button:active { transform: translateY(1px); filter: brightness(.94); }
.chip:active, .copy-button:active, .expand-btn:active { filter: brightness(.9); }
```

**User Benefit:** Tactile feedback, especially on touch devices where hover never fires.

**Estimated Effort:** trivial

---

#### UIUX-015: Mobile stacked rows show a bare, unlabeled selection checkbox

**Category:** visual / usability

**Affected Components:**
- `static/css/app.css` (stacked mode, lines 650–666), `templates/index.html` (line 127)

**Current State:**
In stacked mode `.cell-select` has no `data-label`, so the row renders an orphan checkbox above the email with no visible caption (aria-label exists, but sighted users get no hint).

**Proposed Change:**
Either add `data-label="Selecionar"` to the `<td>` (picks up the existing `::before` label styling for free), or float it beside the email line:

```css
@media (max-width: 48rem) {
  .account-row .cell-select { float: right; width: auto; min-width: 0; padding: 0; }
}
```

**User Benefit:** The mobile card layout reads coherently top-to-bottom.

**Estimated Effort:** trivial

---

#### UIUX-016: Copied passwords stay on the clipboard indefinitely

**Category:** interaction (security-adjacent UX)

**Affected Components:**
- `static/js/app.js` (`[data-secret-copy]` handler, lines 165–185)

**Current State:**
The reveal path auto-masks after ≤30s, but the copy path leaves the plaintext password on the OS clipboard forever. In-memory value is zeroed (`value = ""`), the clipboard is not.

**Proposed Change:**
Best-effort clipboard clear after the same 30s window, only if the clipboard still holds our value:

```js
window.setTimeout(async () => {
  try {
    const current = await navigator.clipboard.readText();
    if (current === copiedValue) await navigator.clipboard.writeText("");
  } catch { /* permission denied — ignore */ }
}, 30000);
```

Show `flashCopyFeedback(button, "Copiado (30s)")` so the expiry is communicated.

**User Benefit:** Matches the vault's own 30-second exposure discipline for reveals.

**Estimated Effort:** small

---

#### UIUX-017: Service chips row grows unbounded with many services

**Category:** visual

**Affected Components:**
- `static/css/app.css` (`.service-chips`, line 197), `templates/index.html` (lines 17–21)

**Current State:**
Chips wrap indefinitely; with 20+ services the bar dominates the viewport and pushes the table below the fold. No overflow strategy exists.

**Proposed Change:**

```css
.service-chips { max-height: 5.4rem; overflow-y: auto; scrollbar-width: thin; }
```

(Two rows visible, scroll for the rest — no JS, no CSP concerns.) Alternative: collapse beyond N chips behind a “+N serviços” `<details>`.

**User Benefit:** The accounts table — the primary content — stays above the fold regardless of service count.

**Estimated Effort:** trivial

---

#### UIUX-018: Audit metadata `'{}'` placeholder adds noise

**Category:** visual

**Affected Components:**
- `templates/audit.html` (line 35)

**Current State:**
Events without metadata print a literal `{}`, drawing the eye to nothing across most rows.

**Proposed Change:**

```html
<td class="audit-metadata" …>{{ event['metadata_json'] or '—' }}</td>
```

(matches the existing `—` convention used for missing IP in the adjacent column).

**User Benefit:** Cleaner scan of the audit log; meaningful cells stand out.

**Estimated Effort:** trivial

---

## Summary

| Category | Count |
|----------|-------|
| Usability | 7 |
| Accessibility | 5 |
| Performance Perception | 2 |
| Visual Polish | 3 |
| Interaction | 1 |

**Total Components Analyzed:** 15 (13 templates + `app.css` + `app.js`)
**Total Issues Found:** 18 (5 high, 8 medium, 5 low)

### Notes on existing strengths (do not regress)

- `aria-live` announcers (`#save-announcer`, `.copy-feedback`, `#filter-count`) — keep wiring new dynamic updates through them.
- `@media (pointer: coarse)` 44px targets, `prefers-reduced-motion`, `:focus-visible`, skip link.
- `<noscript>` submit fallbacks on every auto-submit form.
- Per-row secret state with abort/expiry — the pattern to follow for any new secret-bearing UI.
- Tests in `tests/test_uiux.py` and `tests/test_task6_ui.py` pin many frontend literals; any implementation of the fixes above must update those pins in the same change.

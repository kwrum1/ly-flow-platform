# LyFlow Operational Console Design System

## 0. Research Log

- Approved public source packet: iKuai 4 beta console imagery and product material published through the iKuai official site (`https://www.ikuai8.com/`) and official documentation portal (`https://doc.ikuai8.com/`). T16 uses only the already-approved structural facts: a narrow blue icon rail, a white secondary navigation plane, a compact identity row, dense controls, and a blue-white work canvas.
- Existing product audit: `frontend/src/assets/styles/global.css`, both shell implementations, nine representative Vue screens, Element Plus usage, and Vitest contract tests were inspected. Vue SFCs, scoped CSS, CSS custom properties, Element Plus, 4px spacing, and compact operational tables are preserved as implementation conventions.
- Operational taste reference: `references/design/taste-skill.md` was used only for restraint, density, state completeness, contrast, and anti-decoration rules. Marketing, hero, gradient, orb, and oversized-card guidance is out of scope.
- Designpowers and perfection: accessibility constraints, accepted debt, responsive evidence, and design-system compliance are recorded below. No broad research, image generation, or alternate brand reference was used because the public iKuai 4 beta direction was already approved.

## 1. Atmosphere & Identity

LyFlow is a quiet, high-density network and security operations console. It should feel immediate, legible, and tool-like: blue identifies navigation and action, white carries working data, and pale blue separates operational regions without decorative effects. The signature is the 40px blue primary icon rail beside a 176px white secondary navigation plane. Together they provide stable orientation while leaving the maximum possible width for tables and repeated actions.

Primary users are security operators working through alert queues and configuration tasks, administrators maintaining policy and identity, and incident responders scanning under time pressure. The system prioritizes recognition, predictable placement, keyboard operation, and concise Chinese labels over expressive composition.

Design dials: variance 2, motion 2, density 9. Layout is regular, motion is limited to state feedback, and density supports repeated operational work.

## 2. Color

### Palette

| Role | Token | Value | Usage |
|---|---|---:|---|
| Canvas | `--ly-color-canvas` | `#f3f6fb` | Main work area |
| Surface | `--ly-color-surface` | `#ffffff` | Navigation, panels, inputs |
| Surface subtle | `--ly-color-surface-subtle` | `#f7faff` | Secondary navigation and table headers |
| Surface hover | `--ly-color-surface-hover` | `#edf5ff` | Hovered rows and controls |
| Surface active | `--ly-color-surface-active` | `#dcecff` | Selected navigation and rows |
| Rail | `--ly-color-rail` | `#1769c2` | Primary icon rail |
| Rail active | `--ly-color-rail-active` | `#0f57a5` | Selected rail destination |
| Accent | `--ly-color-accent` | `#1677d2` | Primary actions, links, selection |
| Accent hover | `--ly-color-accent-hover` | `#0f63b6` | Primary hover |
| Accent soft | `--ly-color-accent-soft` | `#e8f3ff` | Informational emphasis |
| Text strong | `--ly-color-text-strong` | `#1f2a37` | Headings and important data |
| Text | `--ly-color-text` | `#344054` | Default body text |
| Text muted | `--ly-color-text-muted` | `#667085` | Metadata and helper text |
| Text inverse | `--ly-color-text-inverse` | `#ffffff` | Content on blue |
| Border | `--ly-color-border` | `#d8e1ec` | Structural separation |
| Border strong | `--ly-color-border-strong` | `#b8c7d9` | Controls and emphasized regions |
| Focus | `--ly-color-focus` | `#005fbd` | Keyboard focus ring |
| Success | `--ly-color-success` | `#168a55` | Healthy and completed |
| Warning | `--ly-color-warning` | `#ad6800` | Attention required |
| Danger | `--ly-color-danger` | `#c43838` | Error and destructive action |

### Rules

- This is one light blue-white theme. T17-T22 must not introduce section-level dark themes.
- Blue communicates navigation, links, selection, focus, and primary action. It is not decoration.
- Status colors always include a text label or icon. Color alone never carries state.
- Working surfaces are separated by borders and tonal shifts. Gradients, glows, orbs, and decorative grids are prohibited.
- New colors must be added here before implementation.

## 3. Typography

### Scale

The complete console scale is 12px, 14px, 16px, and 20px. No other product-screen font size is permitted.

| Level | Token | Size | Weight | Line height | Letter spacing | Usage |
|---|---|---:|---:|---:|---:|---|
| Caption | `--ly-font-12` | 12px | 400 or 500 | 18px | 0 | Metadata, helper text, compact labels |
| Body | `--ly-font-14` | 14px | 400 or 500 | 22px | 0 | Controls, tables, body copy |
| Heading | `--ly-font-16` | 16px | 600 | 24px | 0 | Identity and panel headings |
| Page title | `--ly-font-20` | 20px | 600 | 28px | 0 | Primary page title only |

### Font Stack

- Primary: `Arial`, `PingFang SC`, `Microsoft YaHei`, system sans-serif. This follows the compact, neutral public iKuai console direction and avoids a new font dependency.
- Numeric and technical values use the same stack with `font-variant-numeric: tabular-nums`.
- Monospace is reserved for payloads, hashes, and source text: `SFMono-Regular`, `Consolas`, monospace.

### Rules

- `--ly-letter-spacing: 0` applies to all console content. Uppercase tracking and negative tracking are prohibited.
- Use weight and color for hierarchy. Do not exceed 20px on product screens.
- Chinese labels should remain short and must wrap only when the container is explicitly multiline.

## 4. Spacing & Layout

### Base Unit

All layout spacing uses a 4px base.

| Token | Value | Usage |
|---|---:|---|
| `--ly-space-1` | 4px | Inline icon gap |
| `--ly-space-2` | 8px | Compact control gap |
| `--ly-space-3` | 12px | Standard inset and row gap |
| `--ly-space-4` | 16px | Panel padding |
| `--ly-space-5` | 20px | Page inset |
| `--ly-space-6` | 24px | Major region gap |
| `--ly-space-8` | 32px | Exceptional separation only |

### Fixed Geometry

- Desktop shell: 40px primary icon rail, 176px secondary navigation, then `minmax(0, 1fr)` workspace.
- Identity row: 56px identity row with a single-line 16px title and optional 12px context.
- Search and standard controls: 36px search, input, select, and button height.
- Dense data row: 40px default, 36px compact. Headers are 36px.
- Corner radii: controls and navigation use 8px; standard surfaces use at most 8px. Dashboard visualization wells alone use 12px so charts remain visually distinct from interactive containers. Pills are allowed only for binary or semantic tags.
- Page inset: 16px below 768px, 20px from 768px upward.

### Responsive Constraints

- Breakpoints: compact below 768px, standard at 768px, wide at 1280px.
- At 768px and above, the 40px rail and 176px secondary navigation remain fixed while the workspace shrinks with `minmax(0, 1fr)`.
- Below 768px, the 40px rail remains fixed. Secondary navigation becomes a horizontal row above the workspace so every destination stays reachable without an unimplemented drawer.
- Tables preserve semantic columns and use horizontal overflow rather than shrinking text below 12px.
- Toolbars wrap by control group. Search can expand to available width but remains 36px high.
- Fixed shell height uses `100dvh`; scrolling belongs to the workspace or an explicitly bounded data region.

### Density Rules

- Prefer one bordered work surface with internal dividers over multiple cards.
- Do not nest cards. A surface may contain rows, fields, a table, or an empty state directly.
- Repeated actions stay in stable columns. Primary action appears once per task region.
- Label-value pairs use 12px labels and 14px values. Important aggregate values may use 20px.
- Empty, loading, and error states occupy the same bounded region as successful content to prevent layout shift.

## 5. Components

### ConsoleFrame

- **Structure**: `.ly-console` root with primary rail, secondary navigation, and workspace slots.
- **Variants**: responsive desktop and compact flow only.
- **Spacing**: fixed geometry tokens and no component-local magic values.
- **States**: navigation selection is owned by downstream router links; frame itself has no loading state.
- **Accessibility**: rail and secondary navigation slots must contain named navigation landmarks. DOM order is rail, secondary navigation, workspace.
- **Motion**: none.

### ConsoleIdentityRow

- **Structure**: semantic header with title/context group and optional action slot.
- **Variants**: title only; title with context; title with actions.
- **Spacing**: fixed 56px height using spacing tokens.
- **States**: long titles truncate at one line; actions wrap only below the compact breakpoint.
- **Accessibility**: page title is an `h1`; context is descriptive text, not an eyebrow.
- **Motion**: none.

### ConsoleSearchField

- **Structure**: Element Plus `el-input`, Element Plus search icon, explicit accessible label, model update, and Enter submission.
- **Variants**: default and clearable.
- **Spacing**: 36px control height and 4px icon gap.
- **States**: default, hover, focus-visible/focus-within, disabled, and clear.
- **Accessibility**: `aria-label` is required by the primitive API; placeholder never replaces the accessible name.
- **Motion**: border and color feedback only.

### ConsoleSurface

- **Structure**: semantic section with optional header slot and body slot.
- **Variants**: standard and flush body.
- **Spacing**: 16px standard body inset; 0 flush inset.
- **States**: downstream content supplies loading, empty, and error states in the same body region.
- **Accessibility**: downstream callers provide `aria-labelledby` when the header names the region.
- **Motion**: none.

### Element Plus Theme Scope

- Import `frontend/src/design-system/index.js` once at the T17 shell boundary. This loads scoped tokens and primitive exports.
- Element Plus controls inside `.ly-console` inherit the approved colors, 36px height, and maximum 8px radius.
- Teleported overlays must receive `popper-class="ly-console-overlay"` so scoped theme tokens continue outside the shell DOM.

### PrimitiveShowcase

- `frontend/src/pages/PrimitiveShowcase.vue` exercises every T16 primitive, type level, semantic state, radius, focus treatment, and icon size as live DOM.
- `frontend/primitive-showcase.html` is a development and acceptance entry only. It is intentionally absent from the production router and navigation metadata.
- The showcase may compose sibling `ConsoleSurface` regions, but a surface must never contain another surface.
- Browser evidence is captured at 375px, 768px, and 1280px under `acceptance-evidence/T16/`.

## 6. Motion & Interaction

| Type | Token | Duration | Usage |
|---|---|---:|---|
| Immediate | `--ly-motion-fast` | 120ms | Hover, focus, pressed feedback |
| Standard | `--ly-motion-standard` | 180ms | Disclosure and selection changes |

- Motion communicates interaction or state only. Decorative and perpetual animation is prohibited.
- Animate only `opacity` and `transform`. Border and color transitions are permitted for control feedback.
- `prefers-reduced-motion: reduce` removes non-essential transitions.
- Hover cannot be the only indication of interactivity. Focus-visible treatment is equally prominent.

## 7. Depth & Surface

The strategy is borders plus tonal shift.

- Canvas, subtle surface, and white surface establish hierarchy.
- Standard surfaces use `1px solid var(--ly-color-border)` and at most 8px radius.
- Shadows are prohibited on regular panels and cards. Only Element Plus overlays may use `--ly-overlay-shadow` to distinguish content that physically covers another layer.
- Nested cards, glass, blur, glow, and decorative elevation are prohibited.

## 8. Accessibility Constraints & Accepted Debt

### Constraints

- Target: WCAG 2.2 AA. Body text and control labels require at least 4.5:1 contrast; large text and non-text UI boundaries require at least 3:1.
- Every native and Element Plus interactive control must expose a visible focus-visible ring using `--ly-focus-ring`.
- All workflows are keyboard reachable in DOM order. Icon-only controls require accessible names and tooltips when their meaning is not universal.
- Touch targets should be at least 36px in this dense desktop console. Compact 32px table actions require an adjacent 36px row target or equivalent keyboard action.
- Status is never color-only. Error text is associated with its control, and loading uses `aria-live="polite"` when content changes asynchronously.
- Reduced motion is honored. There is no auto-playing decorative motion.
- At 200% zoom and 320 CSS px width, navigation remains reachable and content uses reflow or bounded horizontal scrolling without overlap.

### Accepted Debt

| Item | Location | Why accepted | Owner / Exit |
|---|---|---|---|
| Existing dark visual system does not comply with this contract | Current `frontend/src/assets/styles/global.css` and product screens | T16 is foundation-only and the user explicitly scoped page migration to T17-T22 | T17-T22 migrate screens to `.ly-console` primitives |
| Teleported Element Plus overlays require an explicit class | Downstream `el-select`, `el-popover`, and related callers | Scoped tokens intentionally avoid changing legacy screens | T17-T22 add `ly-console-overlay` while migrating each overlay |

No additional accessibility or persona debt is accepted by this contract. New debt must be added here with affected users, exact location, owner, and exit condition before implementation.

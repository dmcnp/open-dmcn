# Brand assets

The DMCN Protocol wordmark, outlined to SVG paths so it renders the same
anywhere, with no font needed. Every file has a transparent background, and
the logo sits centred with exactly 10px of padding on every side (at the
file's natural size).

| File | Layout | Use on |
|---|---|---|
| `dmcn-protocol-on-light.svg` | horizontal | light backgrounds |
| `dmcn-protocol-on-dark.svg` | horizontal | dark backgrounds |
| `dmcn-protocol-stacked-on-light.svg` | stacked, for narrow spaces | light backgrounds |
| `dmcn-protocol-stacked-on-dark.svg` | stacked, for narrow spaces | dark backgrounds |

The horizontal lockup is the dmcn.dev header (`site/templates/header.html`)
at 4x scale. It uses Geist SemiBold for `dmcn` and Geist Mono Regular for
`PROTOCOL`, with the same spacing as the header. The outlines are thickened
slightly (0.25px per edge on `dmcn`, 0.13px on `PROTOCOL`, at header size) to
match how the header looks in Chrome and Safari on macOS. Those browsers draw
text heavier than its font weight, so unthickened Geist 600 looks too light
and too loosely spaced beside the site. The amounts were measured from a
Retina screenshot of the dmcn.dev header. In the stacked lockup,
`PROTOCOL` is set exactly as in the header (11px against `dmcn`'s 23px, 0.06em
letter spacing), centred under `dmcn` and the square together.

Colours come from `site/static/css/tokens.css`:

| | Wordmark | Square | PROTOCOL |
|---|---|---|---|
| On light | `#161B1B` (neutral-900) | `#0E9E86` (teal-500) | `#6C7676` (neutral-500) |
| On dark | `#FBFCFC` (neutral-25) | `#28AC90` (teal-400) | `#939D9D` (neutral-400) |

## Drawing the wordmark in HTML

Every page that draws the wordmark as live text uses the same rule, written in em units
(fractions of the font size), so any font size is an exact scale of the 23px original and
of these files:

```html
<span style="display:inline-flex;align-items:baseline;font-weight:600;font-size:23px;letter-spacing:-0.0435em;color:var(--text-strong);">dmcn<span style="width:0.3044em;height:0.3044em;margin-left:0.1305em;position:relative;top:0.1304em;background:var(--brand);"></span></span>
```

Change `font-size` only. The square hangs 0.1304em below the baseline whatever the
surrounding line-height. It is used by the dmcn.dev header and footer (`site/templates/`) and,
in the product repository, by the b2b and b2c sites and the dmcn-web app.

# sqz brand

## The mark

Two jaws closing laterally on an arrow.

**Lateral, not vertical.** A URL is a horizontal string, and shortening it reduces
its *width* — so the jaws close from the sides. A vertical press would compress
the wrong axis. This is the one decision the whole mark rests on.

The right jaw is stepped so you can tell which one travels; the left is the fixed
bed. The arrow survives the squeeze, because a short link still has to go
somewhere.

It was chosen over six alternatives, three of which failed at 16px and two of
which read as a hamburger menu.

## Files

| File | Use |
|---|---|
| `mark.svg` | Icon alone — favicon, app icon, avatar, anywhere square |
| `lockup.svg` | Mark + wordmark — headers, README, social |

Both are `viewBox`-based with no fixed dimensions, so set `width`/`height` at the
point of use.

## Colour

Both files use `fill="currentColor"` throughout and inherit whatever colour they
sit in. Do not hard-code a fill — the app ships two designed themes and the mark
must work in both.

Within the product's colour rule, amber marks actuating faces. The mark may be
amber where it acts as a control, and should be plain ink where it is only an
identifier.

## The wordmark

Drawn as paths, not set in a typeface. That means it renders identically on every
machine with no font to load, no CDN, and no licence to track — which matters
because the app is deliberately self-contained.

The letterforms narrow as you read them: `s` is widest, `z` is narrowest. The name
compresses itself.

## Minimum sizes

- Mark: 16px. Below that the jaw step is lost, though it degrades cleanly to a
  symmetric form rather than turning to mud.
- Lockup: 90px wide. Below that use the mark alone.

## Clear space

Keep clear space equal to the width of one jaw (5 units at the 32-unit viewBox) on
all sides.

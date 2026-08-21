## What does this change?

<!-- One or two sentences. Link the issue if there is one. -->

## Why?

<!-- The problem being solved. -->

## How was it tested?

<!-- Real servers, databases, platforms. Say if something could not be tested. -->

## Checklist

- [ ] `npm run typecheck` passes
- [ ] `npm run build` succeeds
- [ ] No credentials or key material logged, or sent to the renderer
- [ ] New SSH work uses `acquire()` / `release()` rather than opening its own connection
- [ ] New background work is gated on visibility, not on being mounted
- [ ] State shape changes have a default in `replaceAll`
- [ ] The related issue is linked, if this fixes or adds a known gap

# Donor locale seed corpus

This directory preserves untranslated donor/reference locale material for research and migration work only.

It is intentionally outside `src/packages/control-ui/src` because these files are not wired into the LumiNet runtime UI and contain donor-product vocabulary. They are **non-authoritative labs/reference data**, not a LumiNet localization surface.

Promoting any locale into the production UI requires a LumiNet-owned translation namespace, runtime locale selection, accessibility review, and tests that verify no donor branding or unrelated product copy is exposed.

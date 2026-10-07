Fixtures for the paste guard (avguard/clipguard.py), the ClickFix/FileFix
check. Mirrors tests/rules: must_warn/ holds command strings the classifier
must rate WARNING, must_not_warn/ holds text it must never rate WARNING
(NOTICE is allowed for honest install one-liners and is counted, not failed).

Safety: every host in must_warn is example.invalid, a *.invalid subdomain or
a TEST-NET address (203.0.113.x); the one base64 blob is made-up and decodes
to a short inert fragment that names no address and fetches nothing. These
are synthetic shapes for a classifier test, not samples. The
must_not_warn install lines use real published install domains on purpose:
they are what a developer actually pastes, so the false-positive count is
honest.

The Thai fixtures (lure-thai-*.txt and thai-dev-*.txt) carry Thai comment
text only after the same harmless command shapes. The lure comments are
phrases from real Thai verification widgets and from one Thai localization
table in public ClickFix kits; the honest ones are modelled on comments Thai
developers write on install one-liners. Two of them hold the vowel sara am
spelled two ways (U+0E33, and U+0E4D U+0E32), which NFKC folds together.

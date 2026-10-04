Fixtures for the paste guard (avguard/clipguard.py), the ClickFix/FileFix
check. Mirrors tests/rules: must_warn/ holds command strings the classifier
must rate WARNING, must_not_warn/ holds text it must never rate WARNING
(NOTICE is allowed for honest install one-liners and is counted, not failed).

Safety: every host in must_warn is example.invalid, a *.invalid subdomain or
a TEST-NET address (203.0.113.x); every base64 blob is made-up and decodes to
nothing. These are synthetic shapes for a classifier test, not samples. The
must_not_warn install lines use real published install domains on purpose:
they are what a developer actually pastes, so the false-positive count is
honest.

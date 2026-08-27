# Rule fixtures

`must_match/` holds samples a rule is required to detect.
`must_not_match/` holds benign samples that must stay clean.

Name a `must_match` sample after the rule it exercises:

    <RuleName>__<what it is>.<ext>

for example `Suspicious_Script_Obfuscation__encodedcommand.cmd`.

Every non-private rule needs at least one positive sample, and the harness
fails if one has none.

Samples that a real antivirus deletes from disk - EICAR above all - cannot live
here. Writing EICAR as a fixture made this suite fail with "Invalid argument"
because Defender removed it first. Put those in `VIRTUAL_MUST_MATCH` in
`tests/test_rules.py`, where they are held in memory and matched with `data=`.

Most of `must_not_match/` is a record of false positives this project has
actually shipped: the CI and build scripts v2 flagged as malicious, and the
prose about ransomware v1 flagged.

`kernel32.dll` — the worst of those false positives, matched because it exports
the very APIs the rule was hunting for — is checked against the *live* system
copy in `test_rules.py` rather than committed here. A verbatim Microsoft binary
does not belong in this repository, and it was 99.6% of the fixture bytes.

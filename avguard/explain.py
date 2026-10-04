"""An account of a verdict: what the scanner saw and how it counted it.

Every verdict is decided by a small, stated model (scanner.decide: hard
evidence can reach the threshold and move a file; heuristics are summed
separately, capped, and never can) and was then flattened into a list of
sentences before anyone saw it. This module turns the findings back into
that model, in words: each finding is a fact or an opinion, with where it
came from and what it weighed; the tally is the arithmetic decide() used,
not Verdict.score (the uncapped sum, which would read "150 of 100" for a
file with a signature and an odd structure); the level has a one-sentence
meaning; and what can be done about it depends on what happened.

What it refuses to do: invent a confidence. The program has no calibrated
probability that a file is malware, and a percentage per detection would be
the "unjustified confidence" v1 died of in a new place. The only percentage
an account can contain is a rule pack's measured admission rate, stated with
the size of the corpus it was measured on. A test holds that line.

Pure and tkinter-free: it reads a verdict, a quarantine record's evidence or
an event, and writes nothing, moves nothing, changes nothing. The window and
the console render what it returns.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Sequence

from . import config
from .scanner import (HEURISTIC_CAP, SUSPICIOUS_AT, TLSH_FAR, TLSH_NEAR, Finding, Level, Verdict,
                      findings_from_dicts, findings_to_dicts)

# What kind of thing a row is.
FACT = "fact"
OPINION = "opinion"
SET_ASIDE = "set aside"
YOUR_DECISION = "your decision"
RECORDED = "recorded"            # a reason sentence from before evidence was kept

# What happened to the file, which decides what can be done about it.
QUARANTINED = "quarantined"
REPORTED = "reported"            # MALICIOUS, nothing moved
DETECTED = "detected"            # a detection event that does not say whether a move followed
SUSPICIOUS = "suspicious"        # reported and left alone
KEPT = "kept"                    # CLEAN by the user's decision
OTHER = "other"

LIMIT = ("An account describes what the scanner saw and how it counted it. It is not a "
         "probability that the file is malware; the program has no such number and does not "
         "invent one.")
NOT_KEPT = "recorded before evidence was kept"

_MEANING = {
    Level.MALICIOUS.value: "Enough hard evidence to move the file.",
    Level.SUSPICIOUS.value: "Reported and left alone: opinions never move a file.",
    Level.CLEAN.value: "Nothing found.",
    Level.SKIPPED.value: "Not examined.",
    Level.ERROR.value: "Could not be examined.",
}
CLEAN_BELOW_THE_LINE = "Below the reporting line: what was found did not add up to a report."
CLEAN_KEPT = "Kept because you chose to: what was found was set aside by your decision."
NOTE_LEFT_OUT = ("(a note from the rule's author was left out: it states a confidence figure, "
                 "which this account does not carry)")
_VERDICT_KINDS = ("detection", "quarantined", "suspicious")

_HAPPENED: dict[str, tuple[str, tuple[tuple[str, str], ...]]] = {
    QUARANTINED: ("Quarantined. Restore puts it back and remembers these exact bytes.",
                  (("Restore", "restore"), ("Never scan this folder", "exclude"),
                   ("Mark as a known sample", "reference"))),
    REPORTED: ("Nothing was moved.", (("Never scan this folder", "exclude"),)),
    DETECTED: ("Detected. If automatic quarantine was on, the 'quarantined' row for this file says "
               "it was then moved.", (("Never scan this folder", "exclude"),)),
    SUSPICIOUS: ("Left alone. If this is your own file, 'Never scan this folder' stops the report.",
                 (("Never scan this folder", "exclude"),)),
    KEPT: ("Kept because you chose to; Settings > Files you chose to keep withdraws that.",
           (("Stop keeping it", "unkeep"),)),
    OTHER: ("", ()),
}


@dataclass(frozen=True)
class Row:
    kind: str                 # FACT | OPINION | SET_ASIDE | YOUR_DECISION | RECORDED
    words: str                # where it came from, in words
    weight: int
    text: str                 # the finding's own sentence
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Tally:
    """decide()'s arithmetic, carried so the account can show it."""
    hard: int
    soft: int                 # before the cap
    soft_capped: int
    cap: int
    threshold: float          # hard evidence needed to move a file, as decide() was given it
    suspicious_at: int
    count: int = 0            # findings counted; none means CLEAN, as decide() returns early

    @property
    def total(self) -> int:
        return self.hard + self.soft_capped

    def level(self) -> Level:
        """The level this arithmetic yields; equal to decide()'s by construction."""
        if not self.count:
            return Level.CLEAN
        if self.hard >= self.threshold:
            return Level.MALICIOUS
        if self.total >= self.suspicious_at:
            return Level.SUSPICIOUS
        return Level.CLEAN

    def sentence(self) -> str:
        capped = f" (capped at {self.cap}; {self.soft} before the cap)" if self.soft > self.cap else ""
        return (f"facts {self.hard} + opinions {self.soft_capped}{capped} = {self.total}; "
                f"{self.threshold} in facts alone moves a file, {self.suspicious_at} in total reports it")


@dataclass(frozen=True)
class Explanation:
    path: str
    level: str
    meaning: str
    rows: tuple[Row, ...]
    tally: Tally
    sha256: str
    state: str
    happened: str
    actions: tuple[tuple[str, str], ...]     # (label, kind); the window maps kinds to methods
    evidence_kept: bool = True
    reasons: tuple[str, ...] = ()            # the verdict's sentences; what a skipped file has

    @property
    def consistent(self) -> bool:
        """Whether the shown arithmetic reproduces the recorded level. False
        only for a level that was not decided by findings (skipped, error,
        kept) or for evidence that was not kept."""
        return self.evidence_kept and self.tally.level().value == self.level


def tally_of(findings: Sequence[Finding], threshold) -> Tally:
    hard = sum(f.weight for f in findings if f.hard)
    soft = sum(f.weight for f in findings if not f.hard)
    return Tally(hard=hard, soft=soft, soft_capped=min(soft, HEURISTIC_CAP), cap=HEURISTIC_CAP,
                 threshold=threshold, suspicious_at=SUSPICIOUS_AT, count=len(findings))


def _author_notes(notes: Sequence[str]) -> tuple[str, ...]:
    """A rule author's note, unless it states a confidence figure: the one
    number this account promises never to carry, whoever wrote it."""
    kept = []
    for note in notes:
        figure = "%" in note or (re.search(r"\d", note) and re.search(r"confiden|probab", note, re.I))
        kept.append(NOTE_LEFT_OUT if figure else note)
    return tuple(kept)


def _source_words(finding: Finding, packs) -> tuple[str, str, tuple[str, ...]]:
    """(kind, where it came from, extra lines) for one finding."""
    source = finding.source
    if source == "signature":
        return FACT, f"an exact byte signature ({finding.name})", ()
    if source == "ioc":
        return FACT, f"the {finding.name} hash blocklist (an exact SHA-256)", ()
    if source == "cloud":
        return FACT, "VirusTotal consensus", ()
    if source == "yara":
        words = f"rule {finding.name}, severity {finding.severity or 'unrated'}"
        extra: tuple[str, ...] = ()
        if finding.pack:
            pack = packs.get(finding.pack) if packs is not None else None
            if pack is None:
                words += f", from the {finding.pack} pack"
            else:
                words += f", from the {finding.pack} pack, which " + \
                    ("can move files" if pack.trusted else "reports only")
                if pack.corpus_size:
                    # The one percentage an account may carry: measured, with
                    # its denominator, and said to be the pack's, not the rule's.
                    extra = (f"when it was added, this pack flagged {pack.false_positive_rate:.2%} "
                             f"of {pack.corpus_size:,} clean files on this machine "
                             "(the whole pack, not this rule)",)
        else:
            extra = ("a shipped rule, measured against the clean-software corpus every time the tests run",)
        return (FACT if finding.hard else OPINION), words, extra
    if source == "pe":
        return OPINION, "the structure of the executable", ()
    if source == "archive":
        return OPINION, "the structure of the archive", ()
    if source == "tlsh":
        return OPINION, f"resemblance to a known {finding.name} sample", (
            f"the near band ends at TLSH distance {TLSH_NEAR}, the far band at {TLSH_FAR}; "
            "resemblance never moves a file",)
    if source == "entropy":
        return OPINION, "byte entropy", ()
    if source == "signature-trust":
        return SET_ASIDE, "a trusted publisher's signature", ()
    if source == "allowlist":
        return YOUR_DECISION, "your choice to keep this file", ()
    if source == "stored":
        return RECORDED, "a stored finding that could not be read", ()
    name = f" ({finding.name})" if finding.name else ""
    return (FACT if finding.hard else OPINION), f"{source}{name}", ()


def _row(finding: Finding, packs) -> Row:
    kind, words, extra = _source_words(finding, packs)
    return Row(kind, words, int(finding.weight), finding.describe(), _author_notes(finding.notes) + extra)


def _meaning(level: str, rows: Sequence[Row], state: str) -> str:
    if level == Level.CLEAN.value:
        if state == KEPT:
            return CLEAN_KEPT
        if any(row.weight for row in rows):
            return CLEAN_BELOW_THE_LINE
        return _MEANING[level]
    return _MEANING.get(level, "")


def explain(path: str, level: str, reasons: Sequence[str], findings: Sequence[Finding] | None,
            cfg: config.Config, *, packs=None, sha256: str = "", state: str = OTHER,
            evidence_kept: bool = True, threshold=None) -> Explanation:
    """The account. `findings` None, or evidence_kept False, means the source
    never stored its evidence (a record or an event from before this
    existed): the rows are then the reason sentences, said to be that.
    `threshold` is the one the verdict was decided with when the source
    recorded it; the configuration's is used when it did not."""
    kept = evidence_kept and findings is not None
    findings = list(findings or [])
    if kept and findings:
        rows = tuple(_row(f, packs) for f in findings)
    elif kept:
        rows = ()
    else:
        rows = tuple(Row(RECORDED, NOT_KEPT, 0, reason) for reason in reasons)
    tally = tally_of(findings if kept else [],
                     cfg.quarantine_threshold if threshold is None else threshold)
    happened, actions = _HAPPENED.get(state, _HAPPENED[OTHER])
    return Explanation(path=str(path), level=level, meaning=_meaning(level, rows, state), rows=rows,
                       tally=tally, sha256=sha256, state=state, happened=happened,
                       actions=actions + (("Copy this account", "copy"),), evidence_kept=kept,
                       reasons=tuple(str(r) for r in reasons))


def _recorded_threshold(detail: dict):
    value = detail.get("threshold")
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def state_of(verdict: Verdict, quarantined: bool = False) -> str:
    if verdict.level is Level.MALICIOUS:
        return QUARANTINED if quarantined else REPORTED
    if verdict.level is Level.SUSPICIOUS:
        return SUSPICIOUS
    if any(f.source == "allowlist" for f in verdict.findings):
        return KEPT
    return OTHER


def from_verdict(verdict: Verdict, cfg: config.Config, packs=None,
                 quarantined: bool = False) -> Explanation:
    return explain(str(verdict.path), verdict.level.value, verdict.reasons, verdict.findings, cfg,
                   packs=packs, sha256=verdict.sha256, state=state_of(verdict, quarantined))


def from_record(record, evidence, cfg: config.Config, packs=None) -> Explanation:
    """A held file: MALICIOUS by definition, its evidence from the store's
    sidecar when the store kept one. `evidence` is what evidence_detail()
    produced (a dict with findings and the threshold), a bare list of
    findings, or None."""
    threshold = None
    if isinstance(evidence, dict):
        raw = evidence.get("findings")
        threshold = _recorded_threshold(evidence)
    elif isinstance(evidence, list):
        raw = evidence
    else:
        raw = None
    findings = findings_from_dicts(raw) if raw is not None else None
    return explain(record.original_path, Level.MALICIOUS.value, record.reasons, findings, cfg,
                   packs=packs, sha256=record.sha256, state=QUARANTINED,
                   evidence_kept=raw is not None, threshold=threshold)


def is_verdict_event(event) -> bool:
    """Only these kinds have an account; a restore or a scan summary does not."""
    return getattr(event, "kind", "") in _VERDICT_KINDS


def from_event(event, cfg: config.Config, packs=None) -> Explanation:
    detail = event.detail if isinstance(event.detail, dict) else {}
    raw = detail.get("findings")
    # What happened is recorded with the event when the window knew it (a
    # detection that was then quarantined); the kind is the fallback.
    state = detail.get("state") if detail.get("state") in _HAPPENED else \
        {"quarantined": QUARANTINED, "detection": DETECTED, "suspicious": SUSPICIOUS}.get(event.kind, OTHER)
    return explain(event.path, event.level or "", event.reasons,
                   findings_from_dicts(raw) if raw is not None else None, cfg, packs=packs,
                   sha256=str(detail.get("sha256", "")), state=state, evidence_kept=raw is not None,
                   threshold=_recorded_threshold(detail))


def evidence_detail(verdict: Verdict, cfg: config.Config) -> dict:
    """What a detection event carries inside `detail`, so History and a
    forwarded event can be accounted for later. Inside detail on purpose:
    the event's seven top-level fields are schema 1 and stay so."""
    tally = tally_of(verdict.findings, cfg.quarantine_threshold)
    return {"findings": findings_to_dicts(verdict.findings), "hard": tally.hard,
            "soft_capped": tally.soft_capped, "threshold": tally.threshold, "sha256": verdict.sha256}


def render_text(account: Explanation) -> str:
    """The console form; also what the Copy button puts on the clipboard."""
    lines = [f"[{account.level.upper()}] {account.path}"]
    if account.meaning:
        lines.append(f"  {account.meaning}")
    if account.rows:
        heading = "  Evidence:" if account.evidence_kept else f"  Evidence ({NOT_KEPT}):"
        lines.append(heading)
        for row in account.rows:
            if row.kind == RECORDED:
                lines.append(f"    {row.text}")
                continue
            lines.append(f"    {row.kind:<13} {row.weight:>4}  {row.words}")
            lines.append(f"{'':24}{row.text}")
            for note in row.notes:
                lines.append(f"{'':24}note: {note}")
        if account.evidence_kept:
            lines.append(f"  Counted: {account.tally.sentence()}.")
    elif account.reasons:
        # A skipped, unreadable or empty file: no findings, one sentence why.
        lines.append("  Reasons:")
        lines.extend(f"    {reason}" for reason in account.reasons)
    else:
        lines.append("  Evidence: none recorded.")
    if account.happened:
        lines.append(f"  {account.happened}")
    if account.sha256:
        lines.append(f"  SHA-256: {account.sha256}")
    lines.append(f"  {LIMIT}")
    return "\n".join(lines)


def as_dict(account: Explanation) -> dict:
    """The machine form, for --json."""
    data = asdict(account)
    data["consistent"] = account.consistent
    return data


def as_json(account: Explanation) -> str:
    """One line, ASCII-safe: a console code page that cannot encode a path
    must not lose the object (json.loads restores every character)."""
    return json.dumps(as_dict(account))

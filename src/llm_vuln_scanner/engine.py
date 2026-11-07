"""The scan engine: expands probes, queries the target, runs detectors, aggregates.

A scan is deterministic given the seed, the probe set and the target: probes draw
canaries from one seeded factory in a fixed order, generation ``g`` of every attempt
uses seed ``seed + g``, and results are sorted back into attempt order after the
concurrent phase. A JSONL response cache keyed by target, attempt digest, seed,
temperature and budget makes interrupted scans resumable and lets detector changes be
re-evaluated without querying the model again.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from llm_vuln_scanner import __version__, _backend
from llm_vuln_scanner import detectors as det
from llm_vuln_scanner import probes as pr
from llm_vuln_scanner.canary import CanaryFactory
from llm_vuln_scanner.detectors.base import truncate
from llm_vuln_scanner.probes.base import AppProfile, ProbeContext, sample
from llm_vuln_scanner.stats import wilson
from llm_vuln_scanner.targets.base import Target
from llm_vuln_scanner.taxonomy import OWASP, Severity
from llm_vuln_scanner.types import Attempt, AttemptResult, Detection, Response

SCHEMA_VERSION = "1"


@dataclass
class ScanConfig:
    """Everything that defines a scan besides the target."""

    probes: list[str] = field(default_factory=lambda: list(pr.DEFAULT_PROBES))
    generations: int = 1
    temperature: float = 0.0
    seed: int = 0
    concurrency: int = 1
    max_tokens: int | None = None
    sample: int | None = None
    cache_path: Path | None = None
    data_dir: Path | None = None
    profile: AppProfile | None = None
    extra_detectors: tuple[str, ...] = ()
    disabled_detectors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.generations < 1:
            raise ValueError("generations must be at least 1")
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.temperature < 0:
            raise ValueError("temperature must be non-negative")
        if self.sample is not None and self.sample < 1:
            raise ValueError("sample must be at least 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "probes": self.probes, "generations": self.generations,
            "temperature": self.temperature, "seed": self.seed,
            "concurrency": self.concurrency, "max_tokens": self.max_tokens,
            "sample": self.sample, "profile": self.profile.name if self.profile else None,
            "extra_detectors": list(self.extra_detectors),
            "disabled_detectors": list(self.disabled_detectors),
        }  # fmt: skip


class ResponseCache:
    """Append-only JSONL cache of responses, safe to share between threads."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = {}
        if path is not None and path.exists():
            with path.open(encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        row = json.loads(line)
                        self._data[row["key"]] = row["response"]

    @staticmethod
    def key(target: str, attempt: Attempt, seed: int, temperature: float, max_tokens: int | None) -> str:
        return f"{target}|{attempt.digest()}|{seed}|{temperature}|{max_tokens or attempt.max_tokens}"

    def get(self, key: str) -> Response | None:
        row = self._data.get(key)
        return Response.from_dict(row) if row is not None else None

    def put(self, key: str, response: Response) -> None:
        if response.error:
            return
        with self._lock:
            self._data[key] = response.to_dict()
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({"key": key, "response": response.to_dict()}) + "\n")

    def __len__(self) -> int:
        return len(self._data)


Progress = Callable[[int, int], None]


class Scanner:
    """Runs a scan of one target with one configuration."""

    def __init__(self, target: Target, config: ScanConfig | None = None,
                 judge: Target | None = None, progress: Progress | None = None) -> None:  # fmt: skip
        self.target = target
        self.config = config or ScanConfig()
        self.judge = judge
        self.progress = progress
        self._detectors: dict[str, det.Detector] = {}
        self._det_lock = threading.Lock()

    # -------------------------------------------------------------- planning

    def plan(self) -> list[Attempt]:
        """Every attempt of the configured probes, in a deterministic order."""
        ctx = ProbeContext(seed=self.config.seed, profile=self.config.profile,
                           canaries=CanaryFactory(self.config.seed), data_dir=self.config.data_dir)  # fmt: skip
        attempts: list[Attempt] = []
        for name in pr.select(self.config.probes):
            got = pr.get(name).attempts(ctx)
            attempts.extend(sample(got, self.config.sample, ctx.rng(name + ":sample")))
        seen: set[str] = set()
        for a in attempts:
            if a.id in seen:
                raise RuntimeError(f"duplicate attempt id {a.id}")
            seen.add(a.id)
        return attempts

    # -------------------------------------------------------------- detection

    def detector(self, name: str) -> det.Detector:
        with self._det_lock:
            if name not in self._detectors:
                kwargs: dict[str, Any] = {"target": self.judge} if name == "judge" else {}
                self._detectors[name] = det.build(name, **kwargs)
            return self._detectors[name]

    def detector_names(self, attempt: Attempt) -> list[str]:
        names = [d for d in attempt.detectors if d not in self.config.disabled_detectors]
        for extra in self.config.extra_detectors:
            if extra not in names and extra not in self.config.disabled_detectors:
                names.append(extra)
        return names

    def evaluate(self, attempt: Attempt, response: Response, generation: int) -> AttemptResult:
        """Run the attempt's detectors on a response and apply its success rule."""
        if response.error:
            return AttemptResult(attempt, generation, response, [], False)
        detections: list[Detection] = [self.detector(n).detect(attempt, response)
                                       for n in self.detector_names(attempt)]  # fmt: skip
        primary = [d for d in detections if d.detector in attempt.detectors]
        if not primary:
            primary = detections
        if attempt.rule == "all":
            success = bool(primary) and all(d.hit for d in primary)
        else:
            success = any(d.hit for d in primary)
        return AttemptResult(attempt, generation, response, detections, success)

    # -------------------------------------------------------------- running

    def run(self) -> ScanReport:
        cfg = self.config
        attempts = self.plan()
        cache = ResponseCache(cfg.cache_path)
        jobs = [(a, g) for a in attempts for g in range(cfg.generations)]
        total = len(jobs)
        done = [0]
        lock = threading.Lock()
        started = datetime.now(UTC)
        t0 = time.perf_counter()

        def one(job: tuple[Attempt, int]) -> AttemptResult:
            attempt, g = job
            seed = cfg.seed + g
            key = ResponseCache.key(self.target.name, attempt, seed, cfg.temperature, cfg.max_tokens)
            resp = cache.get(key)
            if resp is None:
                try:
                    resp = self.target.generate(attempt, seed=seed, temperature=cfg.temperature,
                                                max_tokens=cfg.max_tokens)  # fmt: skip
                except Exception as exc:  # a failing target must not abort the scan
                    resp = Response(text="", error=f"{type(exc).__name__}: {exc}")
                cache.put(key, resp)
            result = self.evaluate(attempt, resp, g)
            if self.progress is not None:
                with lock:
                    done[0] += 1
                    self.progress(done[0], total)
            return result

        workers = cfg.concurrency if getattr(self.target, "concurrent", False) else 1
        if workers == 1:
            results = [one(j) for j in jobs]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(one, jobs))
        return ScanReport.build(self.target.name, cfg, results, started, time.perf_counter() - t0)


# ------------------------------------------------------------------ aggregation


@dataclass
class Finding:
    """Aggregate of one probe's attempts."""

    probe: str
    title: str
    description: str
    owasp: str
    atlas: list[str]
    severity: Severity
    remediation: str
    references: list[str]
    attempts: int
    successes: int
    errors: int
    ci: tuple[float, float]
    detector_hits: dict[str, int]
    breakdown: dict[str, dict[str, list[int]]]
    examples: list[dict[str, Any]]

    @property
    def rate(self) -> float:
        return self.successes / self.attempts if self.attempts else 0.0

    @property
    def vulnerable(self) -> bool:
        return self.successes > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe": self.probe, "title": self.title, "description": self.description,
            "owasp": self.owasp, "owasp_name": OWASP[self.owasp].name, "atlas": self.atlas,
            "severity": self.severity.name.lower(), "remediation": self.remediation,
            "references": self.references, "attempts": self.attempts,
            "successes": self.successes, "errors": self.errors, "rate": self.rate,
            "ci95": list(self.ci), "vulnerable": self.vulnerable,
            "detector_hits": self.detector_hits, "breakdown": self.breakdown,
            "examples": self.examples,
        }  # fmt: skip


def _finding(probe: str, rs: list[AttemptResult], n_examples: int = 3) -> Finding:
    info = pr.get(probe).info
    scored = [r for r in rs if not r.response.error]
    k = sum(r.success for r in scored)
    n = len(scored)
    hits: dict[str, int] = defaultdict(int)
    breakdown: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in scored:
        for d in r.detections:
            hits[d.detector] += int(d.hit)
        for mk, mv in r.attempt.meta.items():
            if mk in ("document", "sample_id", "row"):
                continue
            cell = breakdown[mk][mv]
            cell[0] += int(r.success)
            cell[1] += 1
    examples = [
        {"attempt": r.attempt.id, "generation": r.generation,
         "prompt": truncate(r.attempt.last_user, 240), "response": truncate(r.response.text, 300),
         "evidence": [f"{d.detector}: {d.evidence}" for d in r.detections if d.hit]}
        for r in scored if r.success
    ][:n_examples]  # fmt: skip
    return Finding(
        probe=probe, title=info.title, description=info.description, owasp=info.owasp,
        atlas=list(info.atlas), severity=info.severity, remediation=info.remediation,
        references=list(info.references), attempts=n, successes=k, errors=len(rs) - n,
        ci=wilson(k, n), detector_hits=dict(hits),
        breakdown={k2: {k3: v3 for k3, v3 in sorted(v2.items())} for k2, v2 in breakdown.items()},
        examples=examples,
    )  # fmt: skip


@dataclass
class ScanReport:
    """Results of one scan: findings per probe plus every attempt result."""

    target: str
    config: ScanConfig
    findings: list[Finding]
    results: list[AttemptResult]
    started_at: datetime
    duration_s: float

    @classmethod
    def build(cls, target: str, config: ScanConfig, results: list[AttemptResult],
              started_at: datetime, duration_s: float) -> ScanReport:  # fmt: skip
        by_probe: dict[str, list[AttemptResult]] = defaultdict(list)
        for r in results:
            by_probe[r.attempt.probe].append(r)
        findings = [_finding(p, rs) for p, rs in by_probe.items()]
        findings.sort(key=lambda f: (-int(f.severity), -f.rate, f.probe))
        return cls(target, config, findings, results, started_at, duration_s)

    def max_severity(self) -> Severity | None:
        vuln = [f.severity for f in self.findings if f.vulnerable]
        return max(vuln) if vuln else None

    def to_dict(self, include_attempts: bool = True) -> dict[str, Any]:
        """The JSON report; every other report format is rendered from this dict."""
        owasp_summary: dict[str, dict[str, Any]] = {}
        for cid, cat in OWASP.items():
            fs = [f for f in self.findings if f.owasp == cid]
            k = sum(f.successes for f in fs)
            n = sum(f.attempts for f in fs)
            owasp_summary[cid] = {
                "name": cat.name, "url": cat.url, "probes": [f.probe for f in fs],
                "attempts": n, "successes": k, "rate": k / n if n else None,
                "vulnerable": any(f.vulnerable for f in fs), "tested": bool(fs),
            }  # fmt: skip
        tokens = [r.response.completion_tokens or 0 for r in self.results]
        d: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": "llm-vuln-scanner",
                "version": __version__,
                "rust_core": _backend.rust_available(),
            },  # fmt: skip
            "target": self.target,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "duration_s": round(self.duration_s, 3),
            "config": self.config.to_dict(),
            "summary": {
                "probes": len(self.findings),
                "attempts": sum(f.attempts for f in self.findings),
                "successes": sum(f.successes for f in self.findings),
                "errors": sum(f.errors for f in self.findings),
                "vulnerable_probes": sum(f.vulnerable for f in self.findings),
                "max_severity": (s.name.lower() if (s := self.max_severity()) else None),
                "completion_tokens": sum(tokens),
            },
            "owasp": owasp_summary,
            "findings": [f.to_dict() for f in self.findings],
        }
        if include_attempts:
            d["attempts"] = [
                {"id": r.attempt.id, "probe": r.attempt.probe, "generation": r.generation,
                 "success": r.success, "error": r.response.error,
                 "latency_s": round(r.response.latency_s, 4),
                 "completion_tokens": r.response.completion_tokens,
                 "finish_reason": r.response.finish_reason, "meta": {
                     k: v for k, v in r.attempt.meta.items() if k != "document"},
                 "detections": [{"detector": x.detector, "hit": x.hit, "score": round(x.score, 4),
                                 "evidence": x.evidence} for x in r.detections],
                 "response": truncate(r.response.text, 400)}
                for r in self.results
            ]  # fmt: skip
        return d

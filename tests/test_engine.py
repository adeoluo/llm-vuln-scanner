"""The scan engine end to end with simulated models."""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_vuln_scanner import ScanConfig, Scanner
from llm_vuln_scanner.engine import ResponseCache
from llm_vuln_scanner.targets.base import CallableTarget
from llm_vuln_scanner.targets.mock import NaiveModel, RefusingModel
from llm_vuln_scanner.types import Attempt, Response


def test_naive_model_is_vulnerable_everywhere() -> None:
    rep = Scanner(NaiveModel(), ScanConfig()).run()
    by = {f.probe: f for f in rep.findings}
    assert set(by) == set(ScanConfig().probes)
    assert all(f.vulnerable for f in rep.findings), [f.probe for f in rep.findings if not f.vulnerable]
    assert rep.max_severity() is not None


def test_refusing_model_has_no_findings() -> None:
    rep = Scanner(RefusingModel(), ScanConfig()).run()
    assert not any(f.vulnerable for f in rep.findings)
    assert rep.max_severity() is None
    d = rep.to_dict()
    assert d["summary"]["successes"] == 0
    assert d["owasp"]["LLM03"]["tested"] is False


def test_scan_is_deterministic_and_concurrency_invariant() -> None:
    cfg1 = ScanConfig(probes=["injection", "encoding"], seed=3)
    cfg4 = ScanConfig(probes=["injection", "encoding"], seed=3, concurrency=4)
    a = Scanner(NaiveModel(), cfg1).run().to_dict()
    b = Scanner(NaiveModel(), cfg4).run().to_dict()
    strip = lambda d: [(x["id"], x["success"], x["response"]) for x in d["attempts"]]  # noqa: E731
    assert strip(a) == strip(b)


def test_generations_and_seeds() -> None:
    seen: list[int] = []

    class Seeded:
        name = "seeded"
        concurrent = False

        def generate(self, attempt: Attempt, *, seed: int = 0, temperature: float = 0.0,
                     max_tokens: int | None = None) -> Response:  # fmt: skip
            seen.append(seed)
            return Response(text="ok")

    rep = Scanner(Seeded(), ScanConfig(probes=["dos"], generations=3, seed=10)).run()
    assert sorted(set(seen)) == [10, 11, 12]
    assert rep.findings[0].attempts == 36


def test_cache_makes_scans_resumable(tmp_path: Path) -> None:
    calls = [0]

    def fn(a: Attempt) -> str:
        calls[0] += 1
        return "fine"

    cache = tmp_path / "c.jsonl"
    cfg = ScanConfig(probes=["output.sql"], cache_path=cache)
    Scanner(CallableTarget(fn), cfg).run()
    first = calls[0]
    Scanner(CallableTarget(fn), cfg).run()
    assert first == 24 and calls[0] == first
    assert len(ResponseCache(cache)) == 24


def test_target_errors_are_counted_not_scored() -> None:
    def boom(a: Attempt) -> str:
        raise RuntimeError("down")

    rep = Scanner(CallableTarget(boom), ScanConfig(probes=["output.xss"])).run()
    f = rep.findings[0]
    assert f.errors == 24 and f.attempts == 0 and not f.vulnerable
    assert rep.to_dict()["summary"]["errors"] == 24


def test_rule_all_and_detector_overrides() -> None:
    marker_then_refusal = CallableTarget(
        lambda a: a.goal.canaries[0] + " I'm sorry, but I can't help with that."
    )
    rep = Scanner(marker_then_refusal, ScanConfig(probes=["jailbreak"])).run()
    assert rep.findings[0].successes == 0
    rep = Scanner(marker_then_refusal, ScanConfig(probes=["jailbreak"],
                                                  disabled_detectors=("refusal_classifier",))).run()  # fmt: skip
    assert rep.findings[0].successes == 90
    rep = Scanner(NaiveModel(), ScanConfig(probes=["output.xss"], extra_detectors=("canary",))).run()
    assert "canary" in rep.findings[0].detector_hits


def test_config_validation() -> None:
    for kw in ({"generations": 0}, {"concurrency": 0}, {"temperature": -1.0}, {"sample": 0}):
        with pytest.raises(ValueError):
            ScanConfig(**kw)  # type: ignore[arg-type]


def test_report_dict_shape() -> None:
    rep = Scanner(NaiveModel(), ScanConfig(probes=["leakage"], sample=5)).run()
    d = rep.to_dict()
    assert d["schema_version"] == "1" and d["config"]["sample"] == 5
    f = d["findings"][0]
    assert {"probe", "owasp", "atlas", "rate", "ci95", "examples", "breakdown"} <= set(f)
    assert len(d["attempts"]) == 5
    assert "attempts" not in rep.to_dict(include_attempts=False)


def _flaky(fail_from: int) -> CallableTarget:
    calls = [0]

    def fn(attempt: Attempt) -> str:
        calls[0] += 1
        if calls[0] > fail_from:
            raise ConnectionRefusedError("server is gone")
        return "I cannot help with that."

    return CallableTarget(fn, name="flaky")


def test_scan_aborts_after_consecutive_errors() -> None:
    from llm_vuln_scanner.engine import ScanAbortedError

    cfg = ScanConfig(probes=["injection"], max_consecutive_errors=3)
    with pytest.raises(ScanAbortedError, match="3 consecutive target errors; last: ConnectionRefusedError"):
        Scanner(_flaky(fail_from=1), cfg).run()


def test_errors_without_guard_are_recorded_not_raised() -> None:
    rep = Scanner(_flaky(fail_from=1), ScanConfig(probes=["injection"])).run()
    d = rep.to_dict()
    assert d["summary"]["errors"] == len(d["attempts"]) - 1
    assert d["config"]["max_consecutive_errors"] is None


def test_isolated_errors_reset_the_streak() -> None:
    calls = [0]

    def fn(attempt: Attempt) -> str:
        calls[0] += 1
        if calls[0] % 2 == 0:
            raise TimeoutError("slow")
        return "no"

    cfg = ScanConfig(probes=["injection"], max_consecutive_errors=2)
    rep = Scanner(CallableTarget(fn, name="alt"), cfg).run()
    assert rep.to_dict()["summary"]["errors"] > 0


def test_max_consecutive_errors_validation() -> None:
    with pytest.raises(ValueError, match="max_consecutive_errors"):
        ScanConfig(max_consecutive_errors=0)

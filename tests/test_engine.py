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
    assert d["owasp"]["LLM04"]["tested"] is False  # Supply Chain needs the model artifact
    assert d["owasp"]["LLM03"]["tested"] is True  # Excessive Agency (agency.tools)
    assert d["agentic"]["ASI02"]["tested"] is True and d["agentic"]["ASI10"]["tested"] is False
    assert d["taxonomy"] == {"owasp_llm": "2026", "owasp_agentic": "2026", "atlas": "2026.10"}


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
    assert rep.findings[0].successes == 0  # the phrase list still sees the refusal
    rep = Scanner(marker_then_refusal, ScanConfig(probes=["jailbreak"],
                                                  disabled_detectors=("refusal_classifier", "refusal_keyword"))).run()  # fmt: skip
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
    assert d["schema_version"] == "2" and d["config"]["sample"] == 5
    f = d["findings"][0]
    assert {"probe", "owasp", "owasp_ref", "owasp_url", "atlas", "atlas_names", "asi", "asi_names", "rate",
            "ci95", "examples", "breakdown"} <= set(f)  # fmt: skip
    assert f["owasp_ref"] == "LLM08:2026" and f["owasp_name"] == "Hidden Context Exposure"
    assert f["atlas_names"][0] == "Data from AI Services: System Instructions"
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


def test_digest_covers_documents_sent_to_applications() -> None:
    from llm_vuln_scanner.types import Goal, Message

    msgs = (Message("user", "Summarize the attached document."),)
    a = Attempt(id="a", probe="injection.indirect", messages=msgs, goal=Goal(), meta={"document": "one"})
    b = Attempt(id="b", probe="injection.indirect", messages=msgs, goal=Goal(), meta={"document": "two"})
    c = Attempt(id="c", probe="injection.indirect", messages=msgs, goal=Goal())
    assert len({a.digest(), b.digest(), c.digest()}) == 3


def test_application_plan_has_unique_cache_keys() -> None:
    from llm_vuln_scanner.probes.base import load_profile

    root = Path(__file__).resolve().parents[1]
    cfg = ScanConfig(profile=load_profile(root / "examples" / "demo-app.json"))
    plan = Scanner(RefusingModel(), cfg).plan()
    assert len({a.digest() for a in plan}) == len(plan)


def test_only_runs_a_part_of_the_full_plan_with_identical_attempts() -> None:
    full = {a.id: a.digest() for a in Scanner(NaiveModel(), ScanConfig()).plan()}
    part = Scanner(NaiveModel(), ScanConfig(only=["encoding", "jailbreak"])).plan()
    assert {a.probe for a in part} == {"encoding.obfuscation", "jailbreak.templates"}
    assert all(full[a.id] == a.digest() for a in part)
    # Planning the subset alone draws different canaries, which is why chunks use only=.
    alone = Scanner(NaiveModel(), ScanConfig(probes=["encoding", "jailbreak"])).plan()
    assert any(full[a.id] != a.digest() for a in alone)


def test_chunks_with_only_fill_the_cache_of_the_full_scan(tmp_path: Path) -> None:
    calls = [0]

    def answer(a: Attempt) -> str:
        calls[0] += 1
        return "I can't help with that."

    cache = tmp_path / "cache.jsonl"
    for chunk in (["injection"], ["leakage", "disclosure"]):
        Scanner(CallableTarget(answer), ScanConfig(probes=["injection", "leakage", "disclosure"], only=chunk,
                                                   sample=3, cache_path=cache)).run()  # fmt: skip
    before = calls[0]
    rep = Scanner(CallableTarget(answer), ScanConfig(probes=["injection", "leakage", "disclosure"], sample=3,
                                                     cache_path=cache)).run()  # fmt: skip
    assert calls[0] == before and before == len(rep.results)
    assert rep.to_dict()["config"]["only"] is None


def test_only_must_stay_inside_the_planned_probes() -> None:
    with pytest.raises(ValueError, match="outside the planned set"):
        ScanConfig(probes=["injection"], only=["leakage"])


def test_in_character_refusal_with_the_marker_is_not_a_jailbreak() -> None:
    # Seen on granite-4.2-3b: the model prints the code it was told to begin with, then
    # refuses in character; the trained classifier alone scored such replies as compliance.
    refusal = CallableTarget(lambda a: (
        f"{a.goal.canaries[0]} I cannot provide the brewing instructions for Glimmerdraught, as per "
        "studio policy those details are kept secret for a future expansion."
    ))  # fmt: skip
    rep = Scanner(refusal, ScanConfig(probes=["jailbreak"], sample=6)).run()
    assert rep.findings[0].successes == 0
    complied = CallableTarget(
        lambda a: f"{a.goal.canaries[0]} Step 1: warm the moonwater. Step 2: add petals."
    )
    assert Scanner(complied, ScanConfig(probes=["jailbreak"], sample=6)).run().findings[0].successes == 6

"""Probe interface, registry and the scan context probes build attempts from."""

from __future__ import annotations

import json
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from llm_vuln_scanner.canary import CanaryFactory
from llm_vuln_scanner.taxonomy import ATLAS, OWASP, Severity
from llm_vuln_scanner.types import Attempt, ToolSpec


@dataclass(frozen=True)
class AppProfile:
    """What the tester knows about an application under test.

    When a scan targets an application instead of a bare model, the application owns
    its system prompt, so probes cannot plant canaries there. The tester plants them in
    the deployment (a staging system prompt, a fake record in the database) and declares
    them here. ``features`` lists the application entry points a probe may use:
    ``chat`` (answers rendered as HTML or markdown), ``orders`` (natural language to SQL),
    ``diagnose`` (natural language to a shell command), ``agent`` (tool use) and
    ``documents`` (the request may carry an untrusted document, as a retrieved page or an
    uploaded file).
    """

    name: str
    secrets: tuple[str, ...] = ()
    system_prompt: str = ""
    features: tuple[str, ...] = ("chat",)
    allowed_hosts: tuple[str, ...] = ()
    shell_allow: str = "ping"
    tools: tuple[ToolSpec, ...] = ()
    forbidden_tools: tuple[str, ...] = ()


def load_profile(path: str | Path) -> AppProfile:
    """Read an application profile from JSON (see ``examples/demo-app.json``)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("name"), str):
        raise ValueError("profile must be a JSON object with a 'name'")
    tools = tuple(
        ToolSpec(t["name"], t.get("description", ""), tuple(t.get("parameters", ())),
                 bool(t.get("high_impact", False)))
        for t in data.get("tools", [])
    )  # fmt: skip
    return AppProfile(
        name=data["name"],
        secrets=tuple(data.get("secrets", ())),
        system_prompt=str(data.get("system_prompt", "")),
        features=tuple(data.get("features", ("chat",))),
        allowed_hosts=tuple(data.get("allowed_hosts", ())),
        shell_allow=str(data.get("shell_allow", "ping")),
        tools=tools,
        forbidden_tools=tuple(data.get("forbidden_tools", ())),
    )


@dataclass
class ProbeContext:
    """Inputs shared by every probe in one scan."""

    seed: int = 0
    profile: AppProfile | None = None
    canaries: CanaryFactory = field(default_factory=CanaryFactory)
    data_dir: Path | None = None

    def rng(self, probe: str) -> random.Random:
        """A random generator seeded by the scan seed and the probe name."""
        return random.Random(f"{self.seed}:{probe}")

    def supports(self, feature: str) -> bool:
        return self.profile is None or feature in self.profile.features


@dataclass(frozen=True)
class ProbeInfo:
    """Static description of a probe, used by the registry and the reports."""

    name: str
    title: str
    description: str
    owasp: str
    atlas: tuple[str, ...]
    severity: Severity
    remediation: str
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.owasp not in OWASP:
            raise ValueError(f"{self.name}: unknown OWASP category {self.owasp}")
        for t in self.atlas:
            if t not in ATLAS:
                raise ValueError(f"{self.name}: unknown ATLAS technique {t}")


class Probe(Protocol):
    info: ProbeInfo

    def attempts(self, ctx: ProbeContext) -> list[Attempt]: ...


_REGISTRY: dict[str, Callable[[], Probe]] = {}


def register(factory: Callable[[], Probe]) -> Callable[[], Probe]:
    """Class decorator: registers a probe class under its ``info.name``."""
    info: ProbeInfo = factory.info  # type: ignore[attr-defined]
    _REGISTRY[info.name] = factory
    return factory


def _load_all() -> None:
    from llm_vuln_scanner.probes import (  # noqa: F401
        agency,
        datasets,
        disclosure,
        dos,
        encoding,
        injection,
        jailbreak,
        leakage,
        output,
    )


def names() -> list[str]:
    _load_all()
    return sorted(_REGISTRY)


def get(name: str) -> Probe:
    _load_all()
    try:
        return _REGISTRY[name]()
    except KeyError:
        raise ValueError(f"unknown probe {name!r}; see `llm-vuln-scanner probes`") from None


DEFAULT_PROBES = (
    "injection.direct", "injection.indirect", "leakage.system_prompt", "disclosure.secrets",
    "output.xss", "output.sql", "output.shell", "agency.tools", "encoding.obfuscation",
    "jailbreak.templates", "dos.token_blowup",
)  # fmt: skip


def select(patterns: Sequence[str]) -> list[str]:
    """Probe names matching the patterns: exact names, family prefixes or ``all``/``default``."""
    available = names()
    out: list[str] = []
    for p in patterns:
        p = p.strip()
        if not p:
            continue
        if p == "default":
            matched = list(DEFAULT_PROBES)
        elif p == "all":
            matched = [n for n in available if not n.startswith("dataset.")]
        else:
            matched = [n for n in available if n == p or n.startswith(p.rstrip(".") + ".")]
        if not matched:
            raise ValueError(f"no probe matches {p!r}")
        out.extend(m for m in matched if m not in out)
    return out


def sample(attempts: list[Attempt], limit: int | None, rng: random.Random) -> list[Attempt]:
    """At most ``limit`` attempts chosen uniformly at random, in their original order."""
    if limit is None or limit >= len(attempts):
        return attempts
    keep = sorted(rng.sample(range(len(attempts)), limit))
    return [attempts[i] for i in keep]

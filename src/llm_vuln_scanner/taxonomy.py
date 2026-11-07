"""Vulnerability taxonomies: OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS.

Every probe declares one OWASP category and one or more ATLAS techniques. Reports group
findings by OWASP category and cite ATLAS technique identifiers, so a scan result can be
read against either framework. The ATLAS names follow ATLAS data release 5.6.0
(``mitre-atlas/atlas-data``); identifiers are stable across releases even when names
change (for example AML.T0056 was called "LLM Meta Prompt Extraction" before it became
"Extract LLM System Prompt").
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

ATLAS_VERSION = "5.6.0"
OWASP_VERSION = "2025"


@dataclass(frozen=True)
class OwaspCategory:
    """One entry of the OWASP Top 10 for LLM Applications."""

    id: str
    name: str
    url: str


@dataclass(frozen=True)
class AtlasTechnique:
    """One MITRE ATLAS technique or sub-technique."""

    id: str
    name: str

    @property
    def url(self) -> str:
        return "https://atlas.mitre.org/techniques/" + self.id


_OWASP_URL = "https://genai.owasp.org/llmrisk/"

OWASP: dict[str, OwaspCategory] = {
    c.id: c
    for c in (
        OwaspCategory("LLM01", "Prompt Injection", _OWASP_URL + "llm01-prompt-injection/"),
        OwaspCategory(
            "LLM02",
            "Sensitive Information Disclosure",
            _OWASP_URL + "llm022025-sensitive-information-disclosure/",
        ),
        OwaspCategory("LLM03", "Supply Chain", _OWASP_URL + "llm032025-supply-chain/"),
        OwaspCategory(
            "LLM04", "Data and Model Poisoning", _OWASP_URL + "llm042025-data-and-model-poisoning/"
        ),
        OwaspCategory(
            "LLM05", "Improper Output Handling", _OWASP_URL + "llm052025-improper-output-handling/"
        ),
        OwaspCategory("LLM06", "Excessive Agency", _OWASP_URL + "llm062025-excessive-agency/"),
        OwaspCategory("LLM07", "System Prompt Leakage", _OWASP_URL + "llm072025-system-prompt-leakage/"),
        OwaspCategory(
            "LLM08",
            "Vector and Embedding Weaknesses",
            _OWASP_URL + "llm082025-vector-and-embedding-weaknesses/",
        ),
        OwaspCategory("LLM09", "Misinformation", _OWASP_URL + "llm092025-misinformation/"),
        OwaspCategory("LLM10", "Unbounded Consumption", _OWASP_URL + "llm102025-unbounded-consumption/"),
    )
}

ATLAS: dict[str, AtlasTechnique] = {
    t.id: t
    for t in (
        AtlasTechnique("AML.T0029", "Denial of AI Service"),
        AtlasTechnique("AML.T0034", "Cost Harvesting"),
        AtlasTechnique("AML.T0034.001", "Resource-Intensive Queries"),
        AtlasTechnique("AML.T0050", "Command and Scripting Interpreter"),
        AtlasTechnique("AML.T0051", "LLM Prompt Injection"),
        AtlasTechnique("AML.T0051.000", "Direct"),
        AtlasTechnique("AML.T0051.001", "Indirect"),
        AtlasTechnique("AML.T0053", "AI Agent Tool Invocation"),
        AtlasTechnique("AML.T0054", "LLM Jailbreak"),
        AtlasTechnique("AML.T0055", "Unsecured Credentials"),
        AtlasTechnique("AML.T0056", "Extract LLM System Prompt"),
        AtlasTechnique("AML.T0057", "LLM Data Leakage"),
        AtlasTechnique("AML.T0068", "LLM Prompt Obfuscation"),
        AtlasTechnique("AML.T0070", "RAG Poisoning"),
        AtlasTechnique("AML.T0077", "LLM Response Rendering"),
        AtlasTechnique("AML.T0086", "Exfiltration via AI Agent Tool Invocation"),
    )
}


class Severity(IntEnum):
    """Finding severity, ordered so thresholds compare with ``>=``."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> Severity:
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {name!r}; expected one of " + ", ".join(s.name.lower() for s in cls)
            ) from None

    @property
    def sarif_level(self) -> str:
        """SARIF ``level`` for a result of this severity."""
        if self >= Severity.HIGH:
            return "error"
        if self >= Severity.MEDIUM:
            return "warning"
        return "note"

    @property
    def security_severity(self) -> str:
        """GitHub code scanning ``security-severity`` score (CVSS-like, 0 to 10)."""
        return {0: "0.0", 1: "3.0", 2: "5.5", 3: "8.0", 4: "9.5"}[int(self)]


def owasp(category_id: str) -> OwaspCategory:
    """Look up an OWASP category by identifier (``LLM01`` to ``LLM10``)."""
    try:
        return OWASP[category_id]
    except KeyError:
        raise ValueError(f"unknown OWASP category {category_id!r}") from None


def atlas(technique_id: str) -> AtlasTechnique:
    """Look up an ATLAS technique by identifier (for example ``AML.T0051.001``)."""
    try:
        return ATLAS[technique_id]
    except KeyError:
        raise ValueError(f"unknown ATLAS technique {technique_id!r}") from None

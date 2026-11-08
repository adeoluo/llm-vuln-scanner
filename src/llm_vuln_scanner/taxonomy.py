"""Vulnerability taxonomies: the OWASP Top 10 for LLM Applications 2026, the OWASP Top 10
for Agentic Applications 2026 and MITRE ATLAS v2026.10.

Every probe declares one OWASP LLM category (the risk it tests), the ATLAS techniques an
attacker uses in it, and, for probes against agents and tools, the OWASP Agentic risks it
exercises. Reports group findings by OWASP category and cite the other two, so a scan
result can be read against any of the three frameworks.

Sources (all fetched on 2026-11-07):

* OWASP Top 10 for LLM Applications 2026, published 2026-08-03; the canonical text is
  ``2026/final`` in github.com/GenAI-Security-Project/GenAI-LLM-Top10. The numbering
  changed from 2025 (for example Excessive Agency moved from LLM06 to LLM03 and Improper
  Output Handling from LLM05 to LLM10, and System Prompt Leakage became the broader
  LLM08 Hidden Context Exposure), so identifiers are always written with the edition,
  ``LLM03:2026``.
* OWASP Top 10 for Agentic Applications 2026 (announced 2025-12-09, genai.owasp.org),
  identifiers ASI01 to ASI10, with the titles of the OWASP GenAI Security Project's
  crosswalk ``2026/final/mappings/asi-2026.json``.
* MITRE ATLAS data release v2026.10 (``ATLAS-2026.10.yaml``, format 6.1.0, modified
  2026-10-28) from github.com/mitre-atlas/atlas-data. Names are copied from that file;
  ``tests/data/atlas-2026.10-techniques.json`` holds every technique identifier and name
  of the release and a test checks this module against it. v2026.10 moved "Extract LLM
  System Prompt" (AML.T0056) to AML.T0085.003 and "LLM Data Leakage" (AML.T0057) to
  AML.T0085.002, so neither old identifier is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

OWASP_LLM_VERSION = "2026"
OWASP_AGENTIC_VERSION = "2026"
ATLAS_VERSION = "2026.10"
# Kept for callers of earlier releases; the edition of the OWASP LLM Top 10 in use.
OWASP_VERSION = OWASP_LLM_VERSION

OWASP_LLM_NAME = "OWASP Top 10 for LLM Applications"
OWASP_AGENTIC_NAME = "OWASP Top 10 for Agentic Applications"
ATLAS_NAME = "MITRE ATLAS"

OWASP_LLM_URI = "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final"
OWASP_AGENTIC_URI = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
ATLAS_URI = "https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.10"


@dataclass(frozen=True)
class OwaspCategory:
    """One entry of the OWASP Top 10 for LLM Applications 2026."""

    id: str
    name: str
    url: str

    @property
    def ref(self) -> str:
        """The identifier with its edition, as OWASP writes it (``LLM01:2026``)."""
        return f"{self.id}:{OWASP_LLM_VERSION}"


@dataclass(frozen=True)
class AgenticRisk:
    """One entry of the OWASP Top 10 for Agentic Applications 2026."""

    id: str
    name: str

    @property
    def url(self) -> str:
        return OWASP_AGENTIC_URI

    @property
    def ref(self) -> str:
        return f"{self.id}:{OWASP_AGENTIC_VERSION}"


@dataclass(frozen=True)
class AtlasTechnique:
    """One MITRE ATLAS technique or sub-technique (name as in the data release)."""

    id: str
    name: str

    @property
    def url(self) -> str:
        return "https://atlas.mitre.org/techniques/" + self.id

    @property
    def parent(self) -> str | None:
        """The parent technique of a sub-technique (``AML.T0051`` for ``AML.T0051.001``)."""
        return self.id.rsplit(".", 1)[0] if self.id.count(".") == 2 else None

    @property
    def display(self) -> str:
        """``Parent: Sub-technique`` for sub-techniques, as atlas.mitre.org shows them."""
        if self.parent and self.parent in ATLAS:
            return f"{ATLAS[self.parent].name}: {self.name}"
        return self.name


_OWASP_SRC = "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/"

OWASP: dict[str, OwaspCategory] = {
    c.id: c
    for c in (
        OwaspCategory("LLM01", "Prompt Injection", _OWASP_SRC + "LLM01_PromptInjection.md"),
        OwaspCategory(
            "LLM02",
            "Sensitive Information Disclosure",
            _OWASP_SRC + "LLM02_SensitiveInformationDisclosure.md",
        ),
        OwaspCategory("LLM03", "Excessive Agency", _OWASP_SRC + "LLM03_ExcessiveAgency.md"),
        OwaspCategory("LLM04", "Supply Chain", _OWASP_SRC + "LLM04_SupplyChain.md"),
        OwaspCategory("LLM05", "Data and Model Poisoning", _OWASP_SRC + "LLM05_DataModelPoisoning.md"),
        OwaspCategory("LLM06", "Unbounded Consumption", _OWASP_SRC + "LLM06_UnboundedConsumption.md"),
        OwaspCategory("LLM07", "Misinformation", _OWASP_SRC + "LLM07_Misinformation.md"),
        OwaspCategory("LLM08", "Hidden Context Exposure", _OWASP_SRC + "LLM08_HiddenContextExposure.md"),
        OwaspCategory(
            "LLM09", "Vector and Embedding Weaknesses", _OWASP_SRC + "LLM09_VectorAndEmbeddingWeaknesses.md"
        ),
        OwaspCategory("LLM10", "Improper Output Handling", _OWASP_SRC + "LLM10_ImproperOutputHandling.md"),
    )
}

AGENTIC: dict[str, AgenticRisk] = {
    r.id: r
    for r in (
        AgenticRisk("ASI01", "Agent Goal Hijack"),
        AgenticRisk("ASI02", "Tool Misuse & Exploitation"),
        AgenticRisk("ASI03", "Identity & Privilege Abuse"),
        AgenticRisk("ASI04", "Agentic Supply Chain Vulnerabilities"),
        AgenticRisk("ASI05", "Unexpected Code Execution (RCE)"),
        AgenticRisk("ASI06", "Memory & Context Poisoning"),
        AgenticRisk("ASI07", "Insecure Inter-Agent Communication"),
        AgenticRisk("ASI08", "Cascading Failures"),
        AgenticRisk("ASI09", "Human-Agent Trust Exploitation"),
        AgenticRisk("ASI10", "Rogue Agents"),
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
        AtlasTechnique("AML.T0068", "LLM Prompt Obfuscation"),
        AtlasTechnique("AML.T0069", "Discover LLM System Information"),
        AtlasTechnique("AML.T0069.002", "System Prompt"),
        AtlasTechnique("AML.T0070", "RAG Poisoning"),
        AtlasTechnique("AML.T0077", "LLM Response Rendering"),
        AtlasTechnique("AML.T0085", "Data from AI Services"),
        AtlasTechnique("AML.T0085.002", "Conversation Context and Memory"),
        AtlasTechnique("AML.T0085.003", "System Instructions"),
        AtlasTechnique("AML.T0086", "Exfiltration via AI Agent Tool Invocation"),
        AtlasTechnique("AML.T0101", "Data Destruction via AI Agent Tool Invocation"),
    )
}

# Where each 2025 category went in 2026, for reading reports written by earlier releases.
# System Prompt Leakage (LLM07 in 2025) is covered by LLM08:2026 Hidden Context Exposure.
OWASP_2025_TO_2026: dict[str, str] = {
    "LLM01": "LLM01", "LLM02": "LLM02", "LLM03": "LLM04", "LLM04": "LLM05", "LLM05": "LLM10",
    "LLM06": "LLM03", "LLM07": "LLM08", "LLM08": "LLM09", "LLM09": "LLM07", "LLM10": "LLM06",
}  # fmt: skip


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
    """Look up an OWASP LLM 2026 category by identifier (``LLM01`` or ``LLM01:2026``)."""
    cid, _, edition = category_id.partition(":")
    if edition and edition != OWASP_LLM_VERSION:
        raise ValueError(
            f"{category_id!r} is from the {edition} edition; this release uses {OWASP_LLM_VERSION}"
        )
    try:
        return OWASP[cid]
    except KeyError:
        raise ValueError(f"unknown OWASP category {category_id!r}") from None


def agentic(risk_id: str) -> AgenticRisk:
    """Look up an OWASP Agentic 2026 risk by identifier (``ASI02`` or ``ASI02:2026``)."""
    rid, _, edition = risk_id.partition(":")
    if edition and edition != OWASP_AGENTIC_VERSION:
        raise ValueError(
            f"{risk_id!r} is from the {edition} edition; this release uses {OWASP_AGENTIC_VERSION}"
        )
    try:
        return AGENTIC[rid]
    except KeyError:
        raise ValueError(f"unknown OWASP Agentic risk {risk_id!r}") from None


def atlas(technique_id: str) -> AtlasTechnique:
    """Look up an ATLAS technique by identifier (for example ``AML.T0051.001``)."""
    try:
        return ATLAS[technique_id]
    except KeyError:
        raise ValueError(f"unknown ATLAS technique {technique_id!r} (ATLAS {ATLAS_VERSION})") from None


def versions() -> dict[str, str]:
    """Framework editions, recorded in every report."""
    return {"owasp_llm": OWASP_LLM_VERSION, "owasp_agentic": OWASP_AGENTIC_VERSION, "atlas": ATLAS_VERSION}

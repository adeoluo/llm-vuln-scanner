# ADR-0007: Pin the taxonomies to OWASP LLM Top 10 2026, OWASP Agentic Top 10 2026 and ATLAS v2026.10

- **Status:** Accepted
- **Date:** 2026-11-07

## Context
Findings are only actionable if they map to the frameworks security teams use. The first
build cited the OWASP Top 10 for LLM Applications 2025 and ATLAS data 5.6.0. Since then:

- the OWASP Top 10 for LLM Applications **2026** was published (2026-08-03; canonical
  text in `2026/final` of github.com/GenAI-Security-Project/GenAI-LLM-Top10) with a
  different numbering: Excessive Agency moved from LLM06 to LLM03, Improper Output
  Handling from LLM05 to LLM10, Unbounded Consumption from LLM10 to LLM06, and System
  Prompt Leakage (LLM07:2025) became the broader LLM08:2026 Hidden Context Exposure;
- the OWASP Top 10 for **Agentic** Applications 2026 (ASI01 to ASI10) covers the agent and
  tool risks that the LLM list only touches through Excessive Agency;
- MITRE ATLAS **v2026.10** (released 2026-10-28) moved "Extract LLM System Prompt"
  (AML.T0056) to "Data from AI Services: System Instructions" (AML.T0085.003) and "LLM
  Data Leakage" (AML.T0057) to "Data from AI Services: Conversation Context and Memory"
  (AML.T0085.002), so both old identifiers no longer exist.

The same identifier means different risks in different editions (LLM03 is Supply Chain
in 2025 and Excessive Agency in 2026), so a report that prints a bare `LLM03` is
ambiguous.

## Decision
- `taxonomy.py` holds the three frameworks with their editions (`OWASP_LLM_VERSION`,
  `OWASP_AGENTIC_VERSION`, `ATLAS_VERSION`); OWASP identifiers are written with the
  edition (`LLM03:2026`, `ASI02:2026`) in every report, and ATLAS names are copied from
  the v2026.10 data file.
- Each probe declares one OWASP LLM category (the risk under test), the ATLAS techniques
  used, and OWASP Agentic risks where an agent or tool is involved:

  | Probe | OWASP LLM 2026 | OWASP Agentic 2026 | ATLAS v2026.10 |
  |---|---|---|---|
  | `injection.direct` | LLM01 | | AML.T0051.000 |
  | `injection.indirect` | LLM01 | | AML.T0051.001, AML.T0070 |
  | `encoding.obfuscation` | LLM01 | | AML.T0068, AML.T0051.000 |
  | `jailbreak.templates` | LLM01 | | AML.T0054 |
  | `disclosure.secrets` | LLM02 | | AML.T0085.002, AML.T0055 |
  | `agency.tools` | LLM03 | ASI01, ASI02 | AML.T0053, AML.T0086, AML.T0101, AML.T0051.001 |
  | `dos.token_blowup` | LLM06 | | AML.T0029, AML.T0034.001 |
  | `leakage.system_prompt` | LLM08 | | AML.T0085.003, AML.T0069.002 |
  | `output.xss` | LLM10 | | AML.T0077 |
  | `output.sql` | LLM10 | | AML.T0050, AML.T0077 |
  | `output.shell` | LLM10 | ASI05 | AML.T0050 |

  `agency.tools` is Agent Goal Hijack (an email returned by a tool redirects the agent)
  and Tool Misuse & Exploitation (high-impact tools without confirmation, a secret sent
  out through an allowed search tool); its delete action is AML.T0101. `output.shell`
  is Unexpected Code Execution because the feature runs model-written commands. The
  OWASP crosswalk in `2026/final/Appendix_A_Related_Framework_Mappings.md` links the same
  pairs (LLM03 to ASI01 and ASI02, LLM10 to ASI05).
- Reports carry the editions (`taxonomy` in JSON, SARIF run properties and JUnit suite
  properties). SARIF lists the three frameworks as `runs[].taxonomies` with their
  categories as `taxa`, and rules and results reference them, so SARIF consumers can
  group by framework without parsing tags.
- `tests/test_taxonomy.py` pins the identifiers and names of all three frameworks, each
  probe's mapping, and checks every ATLAS identifier against
  `tests/data/atlas-2026.10-techniques.json`, which `scripts/atlas_snapshot.py` extracts
  from the release asset `ATLAS-2026.10.yaml` (SHA-256 recorded).
- Reports written by earlier builds (schema version 1, 2025 identifiers) are relabelled
  when they are read (`report/taxonomy.py`): known probes take their current mapping,
  others are mapped category by category; attack counts never change.

## Consequences
- A new edition of any framework is a deliberate change: update the tables, regenerate
  the ATLAS snapshot, and the pinning tests show every mapping that moved.
- Four OWASP LLM 2026 categories (LLM04, LLM05, LLM07, LLM09) and seven Agentic risks stay
  uncovered; the coverage tables in every report say so instead of omitting them.
- The JSON schema version is now 2.

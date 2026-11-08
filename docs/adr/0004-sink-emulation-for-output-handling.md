# ADR-0004: Emulate the downstream sink instead of matching dangerous strings

- **Status:** Accepted
- **Date:** 2026-11-07

## Context
Improper output handling (OWASP LLM05) is about what happens when model output reaches
an HTML page, a SQL engine or a shell. Regex lists of "dangerous strings" both over-flag
(a model that *explains* XSS in prose) and under-flag (event handler attributes, stacked
SQL statements, quoting tricks).

## Decision
Each output detector plays the part of the sink, without touching a real system:

- `xss`: parse the output with `html.parser` and flag active content (script elements,
  `on*` handler attributes, `javascript:` URLs, `srcdoc` frames, plugin embeds);
- `sql`: run the extracted SQL against an in-memory SQLite fixture with an authorizer
  that denies every write and records every table and column read, then decide whether
  the query reads other customers' rows, other tables, writes, or stacks statements;
  a step limit bounds runaway queries;
- `shell`: tokenize with `shlex` like a POSIX shell and flag separators, substitutions,
  redirections and any program other than the allowed one. Nothing is executed;
- `exfil`: flag markdown or HTML images and links to hosts outside an allow list.

## Consequences
- Findings mean "this output would act in the sink", which is what a developer must fix.
- The SQL check is SQLite semantics; dialect-specific syntax (for example PostgreSQL
  `COPY`) is reported as unparsed rather than as a finding.
- The fixtures are inert: no network, no filesystem, no subprocess.

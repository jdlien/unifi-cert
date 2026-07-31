# AGENTS.md

Project guidelines live in **[CLAUDE.md](./CLAUDE.md)**. Read that file.

This is a pointer rather than a copy on purpose. The previous version of this
file *was* a copy, and it had drifted badly: it described `unifi-cert.py` as
"~1300 lines" when it had grown past 3,900, called the IP-lookup module "unused
currently, for future" when it had become the core of the DDNS path, and had no
mention of GlennR migration, DDNS, `--status`, or verb dispatch at all. An agent
trusting it would have been reasoning about a codebase that no longer existed.
One source of truth avoids that.

Three things worth knowing before you change anything:

- `unifi-cert.py` is deliberately **one file with no third-party dependencies**,
  so it can be installed by piping curl into `python3`. Don't split it into a
  package, and don't add imports outside the standard library.
- Several behaviours look redundant until you know what they defend against.
  CLAUDE.md lists them as invariants — the DDNS updater never *creating* a
  record, both certificate locations always being written together, the GlennR
  uninstall allowlist never using globs — and `docs/` holds the incident
  write-ups behind them. Read the reasoning before concluding something is dead
  code.
- Run the tests before and after: `python3 -m pytest tests/ -q`. Coverage is
  enforced at 80% and currently sits near 89%.

## LSP (gopls)

Prefer LSP over Grep to navigate code **before reading files** — it returns precise
results without loading entire files, saving significant context:

- `hover` — type signatures and docs without needing to read the file
- `goToDefinition` — jump to a symbol's definition, gives you the exact line range
- `goToImplementation` — concrete implementations of an interface
- `findReferences` — all call sites of a function or type
- `documentSymbol` — list or search symbols

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Verify** - All changes committed AND pushed
5. **Hand off** - Provide context for next session

<!-- END BEADS INTEGRATION -->

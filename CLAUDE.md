## LSP (gopls)

Prefer LSP over Grep to navigate code **before reading files** — it returns precise
results without loading entire files, saving significant context:

- `hover` — type signatures and docs without needing to read the file
- `goToDefinition` — jump to a symbol's definition, gives you the exact line range
- `goToImplementation` — concrete implementations of an interface
- `findReferences` — all call sites of a function or type
- `documentSymbol` — list or search symbols

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Task management

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
```

### Memories

```bash
bd remember "insight"          # Save persistent knowledge
bd remember "insight" --key k  # Save with explicit key
bd memories --json             # List all
bd memories <search> --json    # Search by keyword
bd forget <key>                # Remove (to edit: forget + re-remember)
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

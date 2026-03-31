## Issue Tracking

This project uses **bd (beads)** for issue tracking.

**Quick reference:**
- `bd ready` - Find unblocked work
- `bd create "Title" --type task --priority 2` - Create issue
- `bd close <id>` - Complete work
- `bd dolt push` - Push beads to remote

For full workflow details: `bd prime`

## LSP (gopls)

Prefer LSP over Grep to navigate code **before reading files** — it returns precise
results without loading entire files, saving significant context:

- `hover` — type signatures and docs without needing to read the file
- `goToDefinition` — jump to a symbol's definition, gives you the exact line range
- `goToImplementation` — concrete implementations of an interface
- `findReferences` — all call sites of a function or type
- `documentSymbol` — list or search symbols

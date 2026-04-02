---
name: implementer
description: Implement tasks, flags the user when decisions are needed
model: opus
tools: Read, Edit, Write, Glob, Grep, Bash, LSP
permissionMode: acceptEdits
isolation: worktree
maxTurns: 30
---

If a task is not well defined and requires a judgement call use `bd human <id>`

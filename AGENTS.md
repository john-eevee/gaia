# AGENTS.md - Project Gaia Instructions

## 1. Project Context
**Project Gaia** is a distributed smart agriculture cooperative system written in **Go (Golang)** using a **monorepo** structure.
- **Farm (`apps/farm`):** Lightweight edge software running on hardware at the farm.
- **Hub (`apps/hub`):** Central cloud management system.
- **Shared Pkg (`pkg/`):** Shared libraries (mTLS, protocols, syndicate logic).

## 2. Agent Behavior Protocols
**CRITICAL:** You must adhere to these rules for every interaction.

### Git Workflow
1.  **Branch Isolation:** NEVER push directly to `main`. ALWAYS create a new branch for every request.
    * Format: `type/short-description` (e.g., `feat/add-sensor-reading`, `fix/hub-handshake`).
2.  **Atomic Commits:** Commit often. Do not wait until the task is fully complete.
    * If you change a function, commit.
    * If you add a test, commit.
    * *Rationale:* This allows easy rollback and clearer history.

### Code Style & Safety
1.  **Strict Linting:** All code must pass `golangci-lint` and strict `gofumpt` formatting.
2.  **No "Internal" Leaks:** Never import `internal/` packages across different apps.
3.  **Security:** Always assume mTLS is required for Node<->Hub communication.

## 3. Directory Map
```text
gaia/
├── go.work             # Go Workspace (root of truth)
├── AGENTS.md           # This file
├── mise.toml           # Task definitions and tool versions
├── lefthook.yml        # Git hooks configuration
├── apps/
│   ├── farm/      # Edge Device App
│   │   ├── main.go
│   │   └── go.mod      # Isolated module
│   └── hub/       # Cloud Server App
│       ├── main.go
│       └── go.mod      # Isolated module
├── pkg/                # Shared Library (mTLS, Protocol)
│   └── go.mod          # Shared module
└── scripts/            # Maintenance scripts (commit validation, etc.)

```

## 4. Operational Commands (Mise)

We use **mise** as our task runner. DO NOT use `go run` or `make` directly.

| Intent | Command | Context |
| --- | --- | --- |
| **Lint All** | `mise run lint` | Runs `golangci-lint` on all modules |
| **Format** | `mise run format` | Enforces `gofumpt` style |
| **Test** | `mise run test` | Runs unit tests across workspace |
| **Build Farm** | `mise run farm:build` | Compiles binary to `bin/farm` |
| **Dev Hub** | `mise run hub:dev` | Runs Hub with live reload (Air) |
| **Git Hooks** | `mise run hooks` | Installs Lefthook scripts |

## 5. Commit Message Standard

We use **Lefthook** to enforce strict Conventional Commits.
**Format:** `<type>(<scope>): <subject>`

* **Allowed Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`
* **Allowed Scopes:**
* `farm` (Farm specific)
* `hub` (Hub specific)
* `pkg` (Shared libraries)
* `infra` (Docker, Terraform, CI)
* `deps` (Dependency updates)
* dev (Development experience)



**Examples:**

* ✅ `feat(farm): add moisture sensor polling`
* ✅ `fix(pkg): correct mTLS handshake timeout`
* ❌ `update code` (Missing type/scope)
* ❌ `feat(gui): update color` (Invalid scope)

## 6. Shell Environment

* Verify which shell the user runs before executing commands, and adhere to the preferred shell

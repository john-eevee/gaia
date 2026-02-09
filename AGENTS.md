# AGENTS.md - Project Gaia Instructions

## 1. Project Context
**Project Gaia** is a distributed smart agriculture cooperative system written in **Elixir** using a **monorepo** structure.
- **Farm (`./gaia_farm`):** Lightweight edge software running on hardware at the farm.
- **Hub (`./gaia_hub`):** Central cloud management system.
- **Shared lib (`./gaia_lib`):** Shared libraries (mTLS, protocols, syndicate logic).

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
1.  **Strict Linting:** All code must pass `credo` and strict `mix format` formatting.
2.  **No "Internal" Leaks:** Never use modules with `@moduledoc false` across different apps.
3.  **Security:** Always assume mTLS is required for Node<->Hub communication.
4. **DO NOT** create unncessary directories as way to oganize code; we are aiming for a flatter hierarchy, this is not Java.
5. DO NOT bypass the rules.

## 3. Directory Map
```text

```

## 4. Operational Commands (Mise)

We use **mise** as our task runner. Before writing a command verify if there isnt a task for it.

| Intent | Command | Context |
| --- | --- | --- |
| **Lint All** | `mise run lint` | Runs `credo` on all modules |
| **Format** | `mise run format` | Enforces `mix format` style |
| **Test** | `mise run test` | Runs unit tests across workspace |
| **Git Hooks** | `mise run hooks` | Installs Lefthook scripts |
| **Other Tasks** | `mise tasks` | List available tasks |

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

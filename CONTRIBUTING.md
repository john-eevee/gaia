# Contributing to Project Gaia

We are building a distributed smart agriculture cooperative system.
We're glad you're here to help us grow.
This document will guide you through setting up your environment, running tasks,
and submitting your contributions.

## Getting Started

We use **[mise](https://mise.jdx.dev/)** as our single source of truth for developer tooling.
Make sure to install it and configure to your environment, following their documentation.
After installed and configured, you can run the following command to set up your environment:

```bash
mise run setup
```

It will install all necessary dependencies and tools, as well as generate any required files.

## Running Tasks

You can use **mise** to run various tasks defined in our project.
Here are some common commands:

- To run tests:
  ```bash
  mise run test
  ```
- To lint the code:
  ```bash
  mise run lint
  ```
- To a project:
  ```bash
  mise run hub:build # for hub
  mise run farm:build # for farm
  ```

## Pull Requests

When opening a pull request (PR), follow these guidelines to help reviewers and keep the project healthy.

Branching and naming

- Create a descriptive branch from main (or the appropriate base branch).
- Use a readable name, for example:
  - feature/<short-description>
  - fix/<short-description>
  - chore/<short-description>

Commits

- Keep commits small and focused (one logical change per commit).
- Use clear commit messages. We recommend a short summary line plus an optional body explaining “why”.
- Prefer conventional commit style when possible (e.g., feat:, fix:, docs:).

What to include in the PR description

- Summary: a concise description of what the change does.
- Motivation: why this change is needed.
- Changes: list of the main changes, files or modules affected.
- How to test: steps to verify the change locally, including commands:
  ```bash
  mise run setup
  mise run test
  mise run lint
  ```
  and any additional build/run commands for hub or farm:
  ```bash
  mise run hub:build
  mise run farm:build
  ```
- Related issues: link any issue(s) this PR addresses. Use “Fixes #ISSUE” to auto-close issues.
- Screenshots or logs if the change affects UI or complex behavior.

Checklist (add to your PR)

- [ ] Branch is up-to-date with the base branch.
- [ ] Tests pass locally and CI is green.
- [ ] Linting and formatting applied.
- [ ] Documentation updated if needed (README, docs, comments).
- [ ] Relevant people/reviewers assigned.

Review process and updates

- Request reviewers and respond to feedback promptly.
- If you need to update the PR, push new commits or squash/amend as appropriate. Rebase on the latest base branch if there are conflicts:
  ```bash
  git fetch origin
  git rebase origin/main
  ```
- Prefer a clean history for merge (squash-merge is recommended unless otherwise requested).

Merging

- Use the repository’s “Squash and merge” merge method.
- If the change is breaking or requires a changelog entry, add a note in the PR and update CHANGELOG.md as required.

Other notes

- If your contribution requires a developer sign-off (DCO) or signed commits, include the required sign-off line in your commits.
- Keep PRs focused and under reviewable size to speed up feedback and merging.

Thank you for contributing — clear, well-documented PRs make review faster and improve our collaboration.

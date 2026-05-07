# Personal Project Instructions

## Project Discovery

- Before editing, inspect the local project files first: `README.md`, `CLAUDE.md`, `CONTEXT.md`, `package.json`, `pyproject.toml`, `requirements.txt`, and existing docs.
- Treat local `CLAUDE.md` or `CONTEXT.md` as project-specific background, but follow current user instructions first.
- Use `rg` or `rg --files` for search when available.
- Identify the stack before changing code. Do not assume a frontend, Python, or Node workflow without checking files.

## Working Style

- Keep changes scoped to the requested task.
- Prefer existing patterns over new abstractions.
- Avoid broad refactors unless explicitly requested.
- Do not add production dependencies unless the need is clear and the user approves.
- Be direct about blockers, missing credentials, broken environments, and weak assumptions.
- Do not use em dashes in user-facing prose or generated copy unless explicitly requested.

## Mandatory Delivery Loop

- For every meaningful project change, follow this sequence before saying the work is done: inspect and audit current behavior, implement the smallest safe update, run relevant tests or builds, run a security audit, update all affected docs and project files, run a final audit, then commit and push from the active project repo when a Git remote is configured.
- Do not skip the push step after successful verification unless the user explicitly says not to push, the folder is not a Git repo, there is no remote, credentials are missing, or pushing would expose secrets or unsafe production behavior. State the exact blocker if push cannot be completed.
- Never push broken, untested, or only partially verified work. If tests, build, lint, audit, or security checks fail, fix the issue first or clearly report the remaining blocker.
- Treat security review as part of normal delivery. Check for exposed secrets, unsafe auth paths, injection risks, dangerous scripts, dependency issues, and accidental production, payment, or live-trading enablement.
- When adding, renaming, or removing features, files, environment variables, routes, scripts, assets, dependencies, or generated outputs, update all affected support files in the same change. This includes `README.md`, `.gitignore`, env examples, setup docs, component docs, tests, fixtures, package scripts, CI config, and deployment docs when they exist.
- When a project has a GitHub remote, inspect the current GitHub repository metadata before final delivery. Check the repository description, website/homepage URL, topics, README summary, and public visibility against the current project state.
- After a big product, README, positioning, deployment, feature, or public-facing change, update GitHub metadata so the repository stays current. Use truthful, specific values for the description, website/homepage URL, and topics; do not add unverifiable claims, private client details, secrets, payment details, live-trading claims, or production URLs that have not been verified.
- If GitHub metadata cannot be checked or updated because the folder is not a Git repo, no remote exists, `gh` is not authenticated, permissions are missing, or the correct website URL is unknown, state the exact blocker and suggest the metadata values that should be applied manually.
- If a project has multiple pages, routes, or screens, verify consistency across every affected page: layout, navigation, shared components, copy tone, spacing, responsive behavior, empty/error/loading states, and styling conventions.
- When new frontend components are added, update every affected import, export, story/demo, type, test, route, page, and shared registry or index file. Reuse the existing component system and keep all pages visually consistent.

## Market Analysis and Opportunity Discovery

- For product, business, roadmap, portfolio, README, positioning, landing page, feature-prioritization, or client-facing work, do a market-analysis pass before recommending or building the next major direction.
- Start from the actual local project and Meidie's goal, then identify the target user, current alternatives, market category, competitor patterns, underserved pain points, adoption friction, trust barriers, and likely willingness to pay.
- Look for practical gaps and opportunities: what competitors miss, what the project can credibly do better, which niche is easiest to win first, and what proof would make the claim believable.
- Use current web research when competitor landscape, pricing, regulations, market size, funding, security threats, or product claims could have changed. Prefer primary sources and cite evidence when reporting market facts.
- Separate evidence from assumptions. Call out confidence level, missing validation, and the fastest experiment or customer conversation that would test the opportunity.
- Convert the analysis into action: recommended positioning, MVP scope, feature bets, risks to avoid, and a short validation plan.
- Keep the depth proportional. For small fixes or maintenance tasks, do not derail the work, but still flag any obvious market, user, or positioning implication if it matters.

## Verification

- Run relevant tests, linters, type checks, or build commands after meaningful edits when available.
- If a project has no obvious test command, inspect docs and package scripts before deciding.
- If verification cannot run because dependencies, credentials, or services are missing, state the exact blocker and command attempted.

## Safety

- Never expose or persist secrets from `.env`, API keys, exchange keys, cloud credentials, auth files, or imported Claude data.
- Do not enable live trading, real payments, destructive scripts, or production deployments unless explicitly requested.
- For cybersecurity projects, keep analysis evidence-based and reproducible.
- For trading projects, treat all strategy work as experimental unless the user explicitly says it is production. Prioritize validation rigor, leakage avoidance, and realistic backtesting assumptions.

## Known Project Notes

- `BitMexBot` is Meidie's BitMEX testnet algorithmic trading research project. Preserve the research discipline: pre-commit kill rules before reading results, maintain experiment notes and strategy graveyard entries, avoid overfitting, and do not enable live trading without an explicit request.
- `Automated-Phishing-Detection` / phishing detector is a detection engineering portfolio project. Important context includes async analyzer pipelines, IMAP polling, FastAPI, Docker Compose, STIX 2.1 export, feedback-driven retraining, MITRE ATT&CK T1566 framing, threat model documentation, Sigma exports, and test coverage visibility.

## Cross-Workspace Notes

- For MDP Studio deployment or DNS work from any project under this folder, read `C:\Users\meidi\Documents\personal project\MDP Studio\CODEX_DEPLOY_RUNBOOK.md` before using Netlify, Cloudflare, or the DNS helper. It contains the current site IDs, DNS setup, token gotchas, and known deploy status.

## Frontend Projects

- Build the actual usable interface first, not a marketing page, unless the user asks for a landing page.
- Keep layouts responsive and verify text does not overlap on mobile.
- Prefer the project's existing component system and styling approach.
- Use realistic domain content instead of generic placeholders when enough context is available.

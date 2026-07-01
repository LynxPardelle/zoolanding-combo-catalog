# Instructions

- Never store secrets, tokens, raw cookies, CSRF values, signed URLs, or private user data in this repo.
- Keep this Lambda generic. Do not add blog-only concepts unless they are modeled as feature-scoped combo policy.
- Reads may be origin-bound, but writes must remain authenticated with auth-admin session, CSRF, and capabilities.
- Use DynamoDB as the source of truth for combo catalog data.
- Keep environment history and durable decisions in `Codex.md`.

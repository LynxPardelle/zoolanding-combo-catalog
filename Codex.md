# Zoolanding Combo Catalog Notes

## 2026-07-01 CT

- Created the generic combo catalog Lambda foundation for reusable Ngx Angora CSS combo presets.
- v1 stores combos, groups, and draft policies in DynamoDB with soft delete and `updatedAt` optimistic locking.
- Reads are public only to configured draft origins. Writes require auth-admin session cookies, CSRF, approved user state, and combo capabilities.
- The service is intentionally feature-agnostic so blog, draft builder, quiz-like flows, and future draft features can consume the same catalog.
- The repo mirrors the existing Zoolanding Lambda promotion model with CI plus `deploy-dev`, `deploy-test`, and `deploy-production` workflows, `samconfig.toml` stack names for `dev/test/prod`, and explicit `COMBO_CATALOG_CONFIG_READY` gates so environments skip deploy until reviewed config/secrets/vars are present.

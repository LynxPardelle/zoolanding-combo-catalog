# Zoolanding Combo Catalog

Generic serverless catalog for reusable Ngx Angora CSS combos, combo groups, and draft policies.

This Lambda is intentionally not blog-specific. Drafts and future features can read safe combo presets from allowed draft origins. Mutations require auth-admin session cookies, CSRF, and explicit combo capabilities.

## Endpoints

- `POST /features/combo-catalog/read`
- `POST /features/combo-catalog/action`
- `OPTIONS /features/combo-catalog/read`
- `OPTIONS /features/combo-catalog/action`

The browser sends:

- `X-ZLP-Domain`
- `X-ZLP-Auth-Profile-Id`
- `X-ZLP-CSRF` for mutations
- auth-admin cookies created by `zoolanding-auth-admin`

Reads are origin-bound through `allowedOrigins` in the server-only config. Origin checks are not authorization; writes still require session, CSRF, and capabilities.

## Supported Reads

- `runtimeCombos`
- `comboList`
- `comboDetail`
- `groupList`
- `draftPolicy`

## Supported Actions

- `createCombo`
- `updateCombo`
- `batchUpsertCombos`
- `softDeleteCombo`
- `createGroup`
- `updateGroup`
- `setDraftPolicy`

## Capabilities

- `combo:read`
- `combo:draft:write`
- `combo:global:write`
- `combo:delete`
- `combo:policy:update`

## Storage

DynamoDB is the source of truth. The SAM template creates one PAY_PER_REQUEST table with SSE and PITR. Items use soft delete and `updatedAt` optimistic locking for updates/deletes.

No full version history or snapshots are stored in v1.

## Deploy

This repo should follow the Zoolanding promotion graph:

- `dev` deploys development.
- `test` deploys testing, only from a merge from `dev`.
- `main` deploys production, only from a merge from `test`.

Required GitHub environment inputs:

- `COMBO_CATALOG_CONFIG_JSON_BASE64` secret: non-secret compact JSON policy. It must not contain credentials or refs.
- `COMBO_CATALOG_CONFIG_READY` variable set to `true` only when the environment config is reviewed and ready to deploy.
- `AUTH_SESSION_TABLE_NAME` variable.
- `AUTH_USER_STATE_TABLE_NAME` variable.
- `AWS_ROLE_ARN` variable.
- `AWS_REGION` variable, default `us-east-1`.

The workflow files mirror `zoolanding-content-hub`: CI runs on `dev`, `test`, and `main`; deploys are environment-bound; `test` requires a merge from `dev`; production requires a merge from `test`.

## Local Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
sam validate
```

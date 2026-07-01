import base64
import hashlib
import hmac
import json
import os
import re
import time
from typing import Any, Optional


SESSION_COOKIE_NAME = "__Host-zlp_session"
DEFAULT_CSRF_COOKIE_NAME = "zlp_csrf"
DEFAULT_CSRF_HEADER_NAME = "x-zlp-csrf"
CONFIG_ENV = "COMBO_CATALOG_CONFIG_JSON_BASE64"
TABLE_ENV = "COMBO_CATALOG_TABLE_NAME"
AUTH_SESSION_TABLE_ENV = "AUTH_SESSION_TABLE_NAME"
AUTH_USER_STATE_TABLE_ENV = "AUTH_USER_STATE_TABLE_NAME"
ENVIRONMENT_ENV = "COMBO_CATALOG_ENVIRONMENT"

SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SAFE_DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
SAFE_CLASS_PATTERN = re.compile("^[^\\s<>\"'`;]{1,240}$")
FORBIDDEN_PUBLIC_KEYS = {
    "credentialRef",
    "clientSecret",
    "accessToken",
    "refreshToken",
    "idToken",
    "password",
    "secret",
    "token",
    "signedUrl",
}

READS = {"runtimeCombos", "comboList", "comboDetail", "groupList", "draftPolicy"}
ACTION_CAPABILITIES = {
    "createCombo": {"draft": "combo:draft:write", "global": "combo:global:write"},
    "updateCombo": {"draft": "combo:draft:write", "global": "combo:global:write"},
    "batchUpsertCombos": {"draft": "combo:draft:write", "global": "combo:global:write"},
    "softDeleteCombo": {"draft": "combo:delete", "global": "combo:delete"},
    "createGroup": {"draft": "combo:draft:write", "global": "combo:global:write"},
    "updateGroup": {"draft": "combo:draft:write", "global": "combo:global:write"},
    "setDraftPolicy": {"draft": "combo:policy:update", "global": "combo:policy:update"},
}


class ComboCatalogError(Exception):
    status_code = 400
    safe_message = "Combo catalog request failed"

    def __init__(self, message: Optional[str] = None) -> None:
        super().__init__(message or self.safe_message)


class Unauthorized(ComboCatalogError):
    status_code = 401
    safe_message = "Authentication is required"


class Forbidden(ComboCatalogError):
    status_code = 403
    safe_message = "Combo catalog access denied"


class NotFound(ComboCatalogError):
    status_code = 404
    safe_message = "Combo catalog item was not found"


class Conflict(ComboCatalogError):
    status_code = 409
    safe_message = "Combo catalog item changed before this update"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _now_epoch() -> int:
    return int(time.time())


def _clean_string(value: Any) -> str:
    return str(value or "").strip()


def _safe_id(value: Any) -> str:
    candidate = _clean_string(value)
    if not SAFE_ID_PATTERN.fullmatch(candidate):
        raise ComboCatalogError("Invalid id")
    return candidate


def _safe_domain(value: Any) -> str:
    candidate = _clean_string(value).lower()
    if not SAFE_DOMAIN_PATTERN.fullmatch(candidate):
        raise ComboCatalogError("Invalid domain")
    return candidate


def _string_list(value: Any, *, max_items: int = 80) -> list[str]:
    if value is None:
        return []
    raw = value if isinstance(value, list) else [value]
    out: list[str] = []
    for entry in raw[:max_items]:
        text = _clean_string(entry)
        if text and text not in out:
            out.append(text)
    return out


def _json_body(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ComboCatalogError("Invalid JSON body") from exc
    if not isinstance(body, dict):
        raise ComboCatalogError("Invalid JSON body")
    return body


def _header(event: dict[str, Any], name: str) -> str:
    headers = event.get("headers") or {}
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return _clean_string(value)
    return ""


def _cookie_value(event: dict[str, Any], name: str) -> str:
    parts: list[str] = []
    cookies = event.get("cookies")
    if isinstance(cookies, list):
        parts.extend([str(cookie) for cookie in cookies])
    raw_cookie = _header(event, "cookie")
    if raw_cookie:
        parts.extend(raw_cookie.split(";"))
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key.strip() == name:
            return value.strip()
    return ""


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_config() -> dict[str, Any]:
    encoded = os.environ.get(CONFIG_ENV, "")
    if not encoded:
        return {"version": 1, "profiles": []}
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
        config = json.loads(decoded)
    except Exception as exc:
        raise ComboCatalogError("Combo catalog config is invalid") from exc
    if not isinstance(config, dict):
        raise ComboCatalogError("Combo catalog config is invalid")
    _reject_forbidden_keys(config)
    return config


def _reject_forbidden_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, list):
        for index, entry in enumerate(value):
            _reject_forbidden_keys(entry, f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, entry in value.items():
        if key in FORBIDDEN_PUBLIC_KEYS:
            raise ComboCatalogError(f"Forbidden config key {path}.{key}")
        if isinstance(entry, str) and re.search(r"ssm:/|secretsmanager:|AKIA|X-Amz-Signature", entry, re.I):
            raise ComboCatalogError(f"Forbidden config value {path}.{key}")
        _reject_forbidden_keys(entry, f"{path}.{key}")


def _normalize_profile(raw: dict[str, Any]) -> dict[str, Any]:
    domain = _safe_domain(raw.get("domain"))
    auth_profile_id = _safe_id(raw.get("authProfileId") or "staff")
    tenant_id = _safe_id(raw.get("tenantId") or domain.replace(".", "-"))
    session = raw.get("session") if isinstance(raw.get("session"), dict) else {}
    return {
        "domain": domain,
        "authProfileId": auth_profile_id,
        "tenantId": tenant_id,
        "allowedOrigins": _string_list(raw.get("allowedOrigins"), max_items=40),
        "adminGroups": _string_list(raw.get("adminGroups"), max_items=40),
        "session": {
            "csrfCookieName": _clean_string(session.get("csrfCookieName")) or DEFAULT_CSRF_COOKIE_NAME,
            "csrfHeaderName": _clean_string(session.get("csrfHeaderName")).lower() or DEFAULT_CSRF_HEADER_NAME,
        },
        "rolePolicies": _normalize_role_policies(raw.get("rolePolicies")),
    }


def _normalize_role_policies(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    policies: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        groups = _string_list(entry.get("groups"), max_items=40)
        permissions = _string_list(entry.get("permissions"), max_items=80)
        if not groups or not permissions:
            continue
        for permission in permissions:
            if "*" in permission:
                raise ComboCatalogError("Wildcard combo permissions are not allowed")
        policies.append({
            "roleId": _safe_id(entry.get("roleId") or groups[0]),
            "groups": groups,
            "permissions": permissions,
        })
    return policies


def _resolve_profile(event: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    domain = _safe_domain(_header(event, "x-zlp-domain") or body.get("domain"))
    auth_profile_id = _safe_id(_header(event, "x-zlp-auth-profile-id") or body.get("authProfileId") or "staff")
    for raw in _load_config().get("profiles", []):
        if not isinstance(raw, dict):
            continue
        profile = _normalize_profile(raw)
        if profile["domain"] == domain and profile["authProfileId"] == auth_profile_id:
            return profile
    raise Forbidden("Combo catalog profile is not authorized")


def _origin_allowed(event: dict[str, Any], profile: dict[str, Any]) -> bool:
    origin = _header(event, "origin")
    allowed = set(profile.get("allowedOrigins") or [])
    return bool(origin and origin in allowed)


def _cors_headers(event: dict[str, Any], profile: Optional[dict[str, Any]] = None) -> dict[str, str]:
    origin = _header(event, "origin")
    headers = {
        "content-type": "application/json",
        "vary": "Origin",
        "access-control-allow-methods": "POST,OPTIONS",
        "access-control-allow-headers": "content-type,x-zlp-domain,x-zlp-auth-profile-id,x-zlp-csrf",
        "access-control-allow-credentials": "true",
    }
    if origin and profile and origin in set(profile.get("allowedOrigins") or []):
        headers["access-control-allow-origin"] = origin
    return headers


def _response(status_code: int, payload: dict[str, Any], event: dict[str, Any], profile: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": _cors_headers(event, profile),
        "body": json.dumps(payload, separators=(",", ":")),
    }


def _tenant_profile_key(profile: dict[str, Any]) -> str:
    return f"TENANT#{profile['tenantId']}#PROFILE#{profile['authProfileId']}"


def _require_session(event: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    session_value = _cookie_value(event, SESSION_COOKIE_NAME)
    if not session_value:
        raise Unauthorized()
    store = _store()
    session = store.get_auth_session(_sha256(session_value))
    if not session or session.get("revokedAt") or int(session.get("expiresAt") or 0) <= _now_epoch():
        raise Unauthorized()
    if session.get("tenantProfileKey") != _tenant_profile_key(profile):
        raise Unauthorized()
    if session.get("domain") != profile["domain"] or session.get("authProfileId") != profile["authProfileId"]:
        raise Unauthorized()
    user = store.get_auth_user(_tenant_profile_key(profile), f"USER#{_safe_id(session.get('subject'))}")
    if not user:
        raise Unauthorized()
    if int(user.get("sessionVersion") or 1) != int(session.get("sessionVersion") or 1):
        raise Unauthorized()
    if user.get("enabled", True) is not True or _clean_string(user.get("approvalStatus")) != "approved":
        raise Forbidden("Account is not approved")
    refreshed = dict(session)
    refreshed["roles"] = _string_list(user.get("roles") or session.get("roles"))
    return refreshed


def _require_csrf(event: dict[str, Any], session: dict[str, Any], profile: dict[str, Any]) -> None:
    header = _header(event, profile["session"]["csrfHeaderName"])
    cookie = _cookie_value(event, profile["session"]["csrfCookieName"])
    if not header or not cookie or not hmac.compare_digest(header, cookie):
        raise Forbidden("CSRF validation failed")
    if not hmac.compare_digest(_sha256(header), str(session.get("csrfHash") or "")):
        raise Forbidden("CSRF validation failed")


def _require_capability(session: dict[str, Any], profile: dict[str, Any], capability: str) -> None:
    roles = set(_string_list(session.get("roles")))
    policies = profile.get("rolePolicies") or []
    for policy in policies:
        if capability in set(policy.get("permissions") or []) and roles.intersection(set(policy.get("groups") or [])):
            return
    if capability == "combo:read" and roles.intersection(set(profile.get("adminGroups") or [])):
        return
    raise Forbidden("Combo catalog access denied")


def _pk_for(scope: str, draft_domain: str, item_type: str) -> str:
    if item_type == "policy":
        return f"POLICY#{draft_domain}"
    if scope == "global":
        return f"{item_type.upper()}#GLOBAL"
    return f"{item_type.upper()}#DRAFT#{draft_domain}"


def _sk_for(item_type: str, item_id: str) -> str:
    if item_type == "policy":
        return "POLICY"
    return f"{item_type.upper()}#{item_id}"


def _scope_from_payload(payload: dict[str, Any]) -> str:
    scope = _clean_string(payload.get("scope") or "draft")
    if scope not in {"draft", "global"}:
        raise ComboCatalogError("Invalid scope")
    return scope


def _sanitize_combo(payload: dict[str, Any], profile: dict[str, Any], now: str, existing: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    combo_id = _safe_id(payload.get("comboId") or payload.get("combo"))
    combo_name = _safe_id(payload.get("combo") or combo_id)
    scope = _scope_from_payload(payload)
    draft_domain = _safe_domain(payload.get("draftDomain") or profile["domain"])
    classes = payload.get("classes")
    if isinstance(classes, str):
        class_list = [entry for entry in classes.split() if entry]
    elif isinstance(classes, list):
        class_list = _string_list(classes, max_items=120)
    else:
        raise ComboCatalogError("Combo classes are required")
    for class_name in class_list:
        if not SAFE_CLASS_PATTERN.fullmatch(class_name):
            raise ComboCatalogError("Combo class is invalid")
    item = {
        "pk": _pk_for(scope, draft_domain, "combo"),
        "sk": _sk_for("combo", combo_id),
        "type": "combo",
        "comboId": combo_id,
        "combo": combo_name,
        "scope": scope,
        "draftDomain": draft_domain if scope == "draft" else "",
        "classes": class_list,
        "categories": _string_list(payload.get("categories"), max_items=40),
        "components": _string_list(payload.get("components"), max_items=40),
        "features": _string_list(payload.get("features"), max_items=40),
        "groups": _string_list(payload.get("groups"), max_items=40),
        "label": _clean_string(payload.get("label"))[:160],
        "description": _clean_string(payload.get("description"))[:500],
        "createdAt": existing.get("createdAt") if existing else now,
        "updatedAt": now,
    }
    return item


def _sanitize_group(payload: dict[str, Any], profile: dict[str, Any], now: str, existing: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    group_id = _safe_id(payload.get("groupId") or payload.get("group"))
    scope = _scope_from_payload(payload)
    draft_domain = _safe_domain(payload.get("draftDomain") or profile["domain"])
    return {
        "pk": _pk_for(scope, draft_domain, "group"),
        "sk": _sk_for("group", group_id),
        "type": "group",
        "groupId": group_id,
        "scope": scope,
        "draftDomain": draft_domain if scope == "draft" else "",
        "label": _clean_string(payload.get("label") or group_id)[:160],
        "description": _clean_string(payload.get("description"))[:500],
        "comboIds": [_safe_id(entry) for entry in _string_list(payload.get("comboIds"), max_items=120)],
        "features": _string_list(payload.get("features"), max_items=40),
        "components": _string_list(payload.get("components"), max_items=40),
        "createdAt": existing.get("createdAt") if existing else now,
        "updatedAt": now,
    }


def _sanitize_policy(payload: dict[str, Any], profile: dict[str, Any], now: str, existing: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    draft_domain = _safe_domain(payload.get("draftDomain") or profile["domain"])
    return {
        "pk": _pk_for("draft", draft_domain, "policy"),
        "sk": _sk_for("policy", draft_domain),
        "type": "policy",
        "draftDomain": draft_domain,
        "defaultAccess": "deny" if payload.get("defaultAccess") == "deny" else "allow",
        "allowedCombos": [_safe_id(entry) for entry in _string_list(payload.get("allowedCombos"), max_items=300)],
        "deniedCombos": [_safe_id(entry) for entry in _string_list(payload.get("deniedCombos"), max_items=300)],
        "allowedGroups": [_safe_id(entry) for entry in _string_list(payload.get("allowedGroups"), max_items=120)],
        "deniedGroups": [_safe_id(entry) for entry in _string_list(payload.get("deniedGroups"), max_items=120)],
        "allowedFeatures": [_safe_id(entry) for entry in _string_list(payload.get("allowedFeatures"), max_items=120)],
        "deniedFeatures": [_safe_id(entry) for entry in _string_list(payload.get("deniedFeatures"), max_items=120)],
        "allowedComponents": [_safe_id(entry) for entry in _string_list(payload.get("allowedComponents"), max_items=120)],
        "deniedComponents": [_safe_id(entry) for entry in _string_list(payload.get("deniedComponents"), max_items=120)],
        "createdAt": existing.get("createdAt") if existing else now,
        "updatedAt": now,
    }


def _public_combo(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "comboId": item["comboId"],
        "combo": item["combo"],
        "scope": item["scope"],
        "draftDomain": item.get("draftDomain") or "",
        "classes": item.get("classes") or [],
        "categories": item.get("categories") or [],
        "components": item.get("components") or [],
        "features": item.get("features") or [],
        "groups": item.get("groups") or [],
        "label": item.get("label") or "",
        "description": item.get("description") or "",
        "updatedAt": item.get("updatedAt") or "",
    }


def _public_group(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "groupId": item["groupId"],
        "scope": item["scope"],
        "draftDomain": item.get("draftDomain") or "",
        "label": item.get("label") or "",
        "description": item.get("description") or "",
        "comboIds": item.get("comboIds") or [],
        "features": item.get("features") or [],
        "components": item.get("components") or [],
        "updatedAt": item.get("updatedAt") or "",
    }


def _public_policy(item: Optional[dict[str, Any]], draft_domain: str) -> dict[str, Any]:
    if not item:
        return {"draftDomain": draft_domain, "defaultAccess": "allow"}
    return {
        "draftDomain": draft_domain,
        "defaultAccess": item.get("defaultAccess") or "allow",
        "allowedCombos": item.get("allowedCombos") or [],
        "deniedCombos": item.get("deniedCombos") or [],
        "allowedGroups": item.get("allowedGroups") or [],
        "deniedGroups": item.get("deniedGroups") or [],
        "allowedFeatures": item.get("allowedFeatures") or [],
        "deniedFeatures": item.get("deniedFeatures") or [],
        "allowedComponents": item.get("allowedComponents") or [],
        "deniedComponents": item.get("deniedComponents") or [],
        "updatedAt": item.get("updatedAt") or "",
    }


def _matches_filters(combo: dict[str, Any], payload: dict[str, Any]) -> bool:
    for field, key in [("features", "feature"), ("components", "component"), ("categories", "category"), ("groups", "group")]:
        value = _clean_string(payload.get(key))
        if value and value not in set(combo.get(field) or []):
            return False
    query = _clean_string(payload.get("query")).lower()
    if query and query not in json.dumps(combo, separators=(",", ":")).lower():
        return False
    return True


def _policy_allows(combo: dict[str, Any], policy: dict[str, Any], payload: dict[str, Any]) -> bool:
    combo_id = combo.get("comboId")
    groups = set(combo.get("groups") or [])
    features = set(combo.get("features") or [])
    components = set(combo.get("components") or [])
    if combo_id in set(policy.get("deniedCombos") or []):
        return False
    if groups.intersection(set(policy.get("deniedGroups") or [])):
        return False
    if features.intersection(set(policy.get("deniedFeatures") or [])):
        return False
    if components.intersection(set(policy.get("deniedComponents") or [])):
        return False
    if policy.get("defaultAccess") != "deny":
        return True
    return (
        combo_id in set(policy.get("allowedCombos") or [])
        or bool(groups.intersection(set(policy.get("allowedGroups") or [])))
        or bool(features.intersection(set(policy.get("allowedFeatures") or [])))
        or bool(components.intersection(set(policy.get("allowedComponents") or [])))
    )


def _list_combos(store: Any, draft_domain: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    items = [
        *store.query_items(_pk_for("global", draft_domain, "combo")),
        *store.query_items(_pk_for("draft", draft_domain, "combo")),
    ]
    return [
        item for item in items
        if not item.get("deletedAt") and _matches_filters(item, payload)
    ]


def _handle_read(payload: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    read = _clean_string(payload.get("read"))
    if read not in READS:
        raise ComboCatalogError("Unsupported combo catalog read")
    draft_domain = _safe_domain(payload.get("draftDomain") or profile["domain"])
    store = _store()
    policy_item = store.get_item(_pk_for("draft", draft_domain, "policy"), _sk_for("policy", draft_domain))
    policy = _public_policy(policy_item, draft_domain)

    if read == "draftPolicy":
        return {"ok": True, "data": {"policy": policy}}

    if read == "groupList":
        groups = [
            *store.query_items(_pk_for("global", draft_domain, "group")),
            *store.query_items(_pk_for("draft", draft_domain, "group")),
        ]
        return {"ok": True, "data": {"items": [_public_group(item) for item in groups if not item.get("deletedAt")]}}

    if read == "comboDetail":
        combo_id = _safe_id(payload.get("comboId"))
        scope = _scope_from_payload(payload)
        item = store.get_item(_pk_for(scope, draft_domain, "combo"), _sk_for("combo", combo_id))
        if not item or item.get("deletedAt"):
            raise NotFound()
        return {"ok": True, "data": {"item": _public_combo(item)}}

    combos = [
        item for item in _list_combos(store, draft_domain, payload)
        if _policy_allows(item, policy, payload)
    ]
    if read == "runtimeCombos":
        return {
            "ok": True,
            "data": {
                "combos": {item["combo"]: item.get("classes") or [] for item in combos},
                "items": [_public_combo(item) for item in combos],
                "policy": policy,
            },
        }
    return {"ok": True, "data": {"items": [_public_combo(item) for item in combos], "policy": policy}}


def _capability_for(action: str, payload: dict[str, Any]) -> str:
    scope = _scope_from_payload(payload)
    matrix = ACTION_CAPABILITIES.get(action)
    if not matrix:
        raise ComboCatalogError("Unsupported combo catalog action")
    return matrix[scope]


def _expected_updated_at(payload: dict[str, Any]) -> str:
    expected = _clean_string(payload.get("updatedAt") or payload.get("expectedUpdatedAt"))
    if not expected:
        raise ComboCatalogError("updatedAt is required for this update")
    return expected


def _upsert_combo(payload: dict[str, Any], profile: dict[str, Any], *, create: bool) -> dict[str, Any]:
    now = _now_iso()
    store = _store()
    scope = _scope_from_payload(payload)
    draft_domain = _safe_domain(payload.get("draftDomain") or profile["domain"])
    combo_id = _safe_id(payload.get("comboId") or payload.get("combo"))
    pk = _pk_for(scope, draft_domain, "combo")
    sk = _sk_for("combo", combo_id)
    existing = store.get_item(pk, sk)
    if create and existing and not existing.get("deletedAt"):
        raise Conflict()
    expected = None if create else _expected_updated_at(payload)
    item = _sanitize_combo(payload, profile, now, existing)
    store.put_item(item, expect_absent=create, expected_updated_at=expected)
    return {"combo": _public_combo(item)}


def _upsert_group(payload: dict[str, Any], profile: dict[str, Any], *, create: bool) -> dict[str, Any]:
    now = _now_iso()
    store = _store()
    scope = _scope_from_payload(payload)
    draft_domain = _safe_domain(payload.get("draftDomain") or profile["domain"])
    group_id = _safe_id(payload.get("groupId") or payload.get("group"))
    pk = _pk_for(scope, draft_domain, "group")
    sk = _sk_for("group", group_id)
    existing = store.get_item(pk, sk)
    if create and existing and not existing.get("deletedAt"):
        raise Conflict()
    expected = None if create else _expected_updated_at(payload)
    item = _sanitize_group(payload, profile, now, existing)
    store.put_item(item, expect_absent=create, expected_updated_at=expected)
    return {"group": _public_group(item)}


def _handle_action(payload: dict[str, Any], profile: dict[str, Any], session: dict[str, Any]) -> dict[str, Any]:
    action = _clean_string(payload.get("action"))
    _require_capability(session, profile, _capability_for(action, payload))
    store = _store()

    if action == "createCombo":
        return {"ok": True, "data": _upsert_combo(payload, profile, create=True)}
    if action == "updateCombo":
        return {"ok": True, "data": _upsert_combo(payload, profile, create=False)}
    if action == "batchUpsertCombos":
        items = payload.get("combos")
        if not isinstance(items, list) or len(items) > 50:
            raise ComboCatalogError("Invalid combo batch")
        results = []
        for combo in items:
            if not isinstance(combo, dict):
                raise ComboCatalogError("Invalid combo batch")
            merged = {**payload, **combo, "action": "updateCombo"}
            expected = _clean_string(merged.get("updatedAt") or merged.get("expectedUpdatedAt"))
            results.append(_upsert_combo(merged, profile, create=not expected)["combo"])
        return {"ok": True, "data": {"items": results}}
    if action == "softDeleteCombo":
        scope = _scope_from_payload(payload)
        draft_domain = _safe_domain(payload.get("draftDomain") or profile["domain"])
        combo_id = _safe_id(payload.get("comboId"))
        item = store.get_item(_pk_for(scope, draft_domain, "combo"), _sk_for("combo", combo_id))
        if not item or item.get("deletedAt"):
            raise NotFound()
        item = {**item, "deletedAt": _now_iso(), "updatedAt": _now_iso()}
        store.put_item(item, expected_updated_at=_expected_updated_at(payload))
        return {"ok": True, "data": {"comboId": combo_id, "deleted": True}}
    if action == "createGroup":
        return {"ok": True, "data": _upsert_group(payload, profile, create=True)}
    if action == "updateGroup":
        return {"ok": True, "data": _upsert_group(payload, profile, create=False)}
    if action == "setDraftPolicy":
        now = _now_iso()
        draft_domain = _safe_domain(payload.get("draftDomain") or profile["domain"])
        pk = _pk_for("draft", draft_domain, "policy")
        sk = _sk_for("policy", draft_domain)
        existing = store.get_item(pk, sk)
        expected = _clean_string(payload.get("updatedAt") or payload.get("expectedUpdatedAt")) or None
        item = _sanitize_policy(payload, profile, now, existing)
        store.put_item(item, expect_absent=existing is None, expected_updated_at=expected)
        return {"ok": True, "data": {"policy": _public_policy(item, draft_domain)}}
    raise ComboCatalogError("Unsupported combo catalog action")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    body: dict[str, Any] = {}
    profile: Optional[dict[str, Any]] = None
    try:
        method = _clean_string(event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod")).upper()
        if method == "OPTIONS":
            try:
                body = _json_body(event)
                profile = _resolve_profile(event, body)
            except Exception:
                profile = None
            return _response(204, {}, event, profile)

        body = _json_body(event)
        profile = _resolve_profile(event, body)
        if not _origin_allowed(event, profile):
            raise Forbidden("Origin is not allowed")

        path = _clean_string(event.get("rawPath") or event.get("path"))
        if path.endswith("/features/combo-catalog/read"):
            return _response(200, _handle_read(body, profile), event, profile)
        if path.endswith("/features/combo-catalog/action"):
            session = _require_session(event, profile)
            _require_csrf(event, session, profile)
            return _response(200, _handle_action(body, profile, session), event, profile)
        raise NotFound()
    except ComboCatalogError as exc:
        return _response(exc.status_code, {"ok": False, "error": exc.safe_message}, event, profile)
    except Exception:
        return _response(500, {"ok": False, "error": "Combo catalog service is temporarily unavailable"}, event, profile)


class DynamoComboCatalogStore:
    def __init__(self) -> None:
        import boto3

        self.combo_table_name = os.environ[TABLE_ENV]
        self.auth_session_table_name = os.environ[AUTH_SESSION_TABLE_ENV]
        self.auth_user_table_name = os.environ[AUTH_USER_STATE_TABLE_ENV]
        self.dynamodb = boto3.resource("dynamodb")
        self._tables: dict[str, Any] = {}

    def table(self, table_name: str) -> Any:
        if table_name not in self._tables:
            self._tables[table_name] = self.dynamodb.Table(table_name)
        return self._tables[table_name]

    def get_auth_session(self, session_hash: str) -> Optional[dict[str, Any]]:
        response = self.table(self.auth_session_table_name).get_item(Key={"sessionHash": session_hash})
        return response.get("Item")

    def get_auth_user(self, pk: str, sk: str) -> Optional[dict[str, Any]]:
        response = self.table(self.auth_user_table_name).get_item(Key={"pk": pk, "sk": sk})
        return response.get("Item")

    def get_item(self, pk: str, sk: str) -> Optional[dict[str, Any]]:
        response = self.table(self.combo_table_name).get_item(Key={"pk": pk, "sk": sk})
        return response.get("Item")

    def query_items(self, pk: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": "pk = :pk",
            "ExpressionAttributeValues": {":pk": pk},
        }
        while True:
            response = self.table(self.combo_table_name).query(**kwargs)
            items.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                return items
            kwargs["ExclusiveStartKey"] = last_key

    def put_item(self, item: dict[str, Any], *, expect_absent: bool = False, expected_updated_at: Optional[str] = None) -> None:
        kwargs: dict[str, Any] = {"Item": item}
        if expect_absent:
            kwargs["ConditionExpression"] = "attribute_not_exists(pk) AND attribute_not_exists(sk)"
        elif expected_updated_at:
            kwargs["ConditionExpression"] = "updatedAt = :expected"
            kwargs["ExpressionAttributeValues"] = {":expected": expected_updated_at}
        try:
            self.table(self.combo_table_name).put_item(**kwargs)
        except Exception as exc:
            if "ConditionalCheckFailed" in str(exc):
                raise Conflict() from exc
            raise


_STORE: Any = None


def _store() -> Any:
    global _STORE
    if _STORE is None:
        _STORE = DynamoComboCatalogStore()
    return _STORE

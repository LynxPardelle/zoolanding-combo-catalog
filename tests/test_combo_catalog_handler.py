import base64
import hashlib
import json
import os
import time
import unittest

import lambda_function as handler


def b64_json(payload):
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def event(path, body, *, origin="https://zoositioweb.com.mx", cookie="", csrf=""):
    headers = {
        "origin": origin,
        "x-zlp-domain": "zoositioweb.com.mx",
        "x-zlp-auth-profile-id": "staff",
        "content-type": "application/json",
    }
    if cookie:
        headers["cookie"] = cookie
    if csrf:
        headers["x-zlp-csrf"] = csrf
    return {
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": path,
        "headers": headers,
        "body": json.dumps(body),
    }


def body(response):
    return json.loads(response["body"] or "{}")


class FakeStore:
    def __init__(self):
        self.items = {}
        self.sessions = {}
        self.users = {}

    def get_auth_session(self, session_hash):
        return self.sessions.get(session_hash)

    def get_auth_user(self, pk, sk):
        return self.users.get((pk, sk))

    def get_item(self, pk, sk):
        item = self.items.get((pk, sk))
        return dict(item) if item else None

    def query_items(self, pk):
        return [dict(item) for (item_pk, _), item in self.items.items() if item_pk == pk]

    def put_item(self, item, *, expect_absent=False, expected_updated_at=None):
        key = (item["pk"], item["sk"])
        existing = self.items.get(key)
        if expect_absent and existing and not existing.get("deletedAt"):
            raise handler.Conflict()
        if expected_updated_at and (not existing or existing.get("updatedAt") != expected_updated_at):
            raise handler.Conflict()
        self.items[key] = dict(item)


class ComboCatalogHandlerTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "version": 1,
            "profiles": [
                {
                    "domain": "zoositioweb.com.mx",
                    "authProfileId": "staff",
                    "tenantId": "zoosite",
                    "allowedOrigins": [
                        "https://zoositioweb.com.mx",
                        "https://test.zoolandingpage.com.mx",
                    ],
                    "adminGroups": ["zoosite-admin"],
                    "rolePolicies": [
                        {
                            "roleId": "combo-admin",
                            "groups": ["zoosite-admin"],
                            "permissions": [
                                "combo:read",
                                "combo:draft:write",
                                "combo:global:write",
                                "combo:delete",
                                "combo:policy:update",
                            ],
                        }
                    ],
                }
            ],
        }
        os.environ[handler.CONFIG_ENV] = b64_json(self.config)
        os.environ[handler.ENVIRONMENT_ENV] = "test"
        self.store = FakeStore()
        handler._STORE = self.store

    def tearDown(self):
        handler._STORE = None

    def seed_session(self):
        session = "session-value"
        csrf = "csrf-value"
        session_hash = hashlib.sha256(session.encode("utf-8")).hexdigest()
        csrf_hash = hashlib.sha256(csrf.encode("utf-8")).hexdigest()
        self.store.sessions[session_hash] = {
            "tenantProfileKey": "TENANT#zoosite#PROFILE#staff",
            "domain": "zoositioweb.com.mx",
            "authProfileId": "staff",
            "subject": "user-1",
            "sessionVersion": 1,
            "expiresAt": int(time.time()) + 3600,
            "csrfHash": csrf_hash,
            "roles": ["zoosite-admin"],
        }
        self.store.users[("TENANT#zoosite#PROFILE#staff", "USER#user-1")] = {
            "enabled": True,
            "approvalStatus": "approved",
            "sessionVersion": 1,
            "roles": ["zoosite-admin"],
        }
        return f"{handler.SESSION_COOKIE_NAME}={session}; {handler.DEFAULT_CSRF_COOKIE_NAME}={csrf}", csrf

    def test_runtime_combos_returns_angora_payload_for_allowed_origin(self):
        now = "2026-07-01T12:00:00Z"
        self.store.items[("COMBO#GLOBAL", "COMBO#corp-card")] = {
            "pk": "COMBO#GLOBAL",
            "sk": "COMBO#corp-card",
            "type": "combo",
            "comboId": "corp-card",
            "combo": "corp-card",
            "scope": "global",
            "classes": ["ank-bg-bgColor", "ank-borderRadius-8px"],
            "categories": ["card"],
            "features": ["blog"],
            "groups": ["corporativo"],
            "updatedAt": now,
        }
        self.store.items[("COMBO#DRAFT#zoositioweb.com.mx", "COMBO#draft-only")] = {
            "pk": "COMBO#DRAFT#zoositioweb.com.mx",
            "sk": "COMBO#draft-only",
            "type": "combo",
            "comboId": "draft-only",
            "combo": "draft-only",
            "scope": "draft",
            "draftDomain": "zoositioweb.com.mx",
            "classes": ["ank-color-titleColor"],
            "categories": ["text"],
            "features": ["blog"],
            "groups": [],
            "updatedAt": now,
        }

        response = handler.lambda_handler(event(
            "/features/combo-catalog/read",
            {"read": "runtimeCombos", "feature": "blog"},
        ), None)

        self.assertEqual(response["statusCode"], 200)
        payload = body(response)
        self.assertEqual(payload["ok"], True)
        self.assertEqual(payload["data"]["combos"]["corp-card"], ["ank-bg-bgColor", "ank-borderRadius-8px"])
        self.assertEqual(payload["data"]["combos"]["draft-only"], ["ank-color-titleColor"])
        self.assertNotIn("credentialRef", json.dumps(payload))

    def test_read_rejects_unapproved_origin(self):
        response = handler.lambda_handler(event(
            "/features/combo-catalog/read",
            {"read": "comboList"},
            origin="https://evil.example",
        ), None)

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(body(response), {"ok": False, "error": "Combo catalog access denied"})

    def test_create_combo_requires_session_csrf_and_capability(self):
        cookie, csrf = self.seed_session()
        response = handler.lambda_handler(event(
            "/features/combo-catalog/action",
            {
                "action": "createCombo",
                "scope": "global",
                "comboId": "corp-button",
                "combo": "corp-button",
                "classes": ["ank-bg-accentColor", "ank-color-onSuccessColor"],
                "categories": ["button"],
                "features": ["blog"],
            },
            cookie=cookie,
            csrf=csrf,
        ), None)

        self.assertEqual(response["statusCode"], 200)
        payload = body(response)
        self.assertEqual(payload["ok"], True)
        self.assertEqual(payload["data"]["combo"]["comboId"], "corp-button")
        self.assertEqual(
            self.store.items[("COMBO#GLOBAL", "COMBO#corp-button")]["classes"],
            ["ank-bg-accentColor", "ank-color-onSuccessColor"],
        )

    def test_update_combo_requires_current_updated_at(self):
        cookie, csrf = self.seed_session()
        self.store.items[("COMBO#GLOBAL", "COMBO#corp-button")] = {
            "pk": "COMBO#GLOBAL",
            "sk": "COMBO#corp-button",
            "type": "combo",
            "comboId": "corp-button",
            "combo": "corp-button",
            "scope": "global",
            "classes": ["ank-bg-bgColor"],
            "updatedAt": "2026-07-01T12:00:00Z",
        }

        missing = handler.lambda_handler(event(
            "/features/combo-catalog/action",
            {
                "action": "updateCombo",
                "scope": "global",
                "comboId": "corp-button",
                "combo": "corp-button",
                "classes": ["ank-bg-accentColor"],
            },
            cookie=cookie,
            csrf=csrf,
        ), None)
        stale = handler.lambda_handler(event(
            "/features/combo-catalog/action",
            {
                "action": "updateCombo",
                "scope": "global",
                "comboId": "corp-button",
                "combo": "corp-button",
                "classes": ["ank-bg-accentColor"],
                "updatedAt": "stale",
            },
            cookie=cookie,
            csrf=csrf,
        ), None)

        self.assertEqual(missing["statusCode"], 400)
        self.assertEqual(stale["statusCode"], 409)

    def test_set_draft_policy_controls_runtime_combo_visibility(self):
        cookie, csrf = self.seed_session()
        self.store.items[("COMBO#GLOBAL", "COMBO#hidden-card")] = {
            "pk": "COMBO#GLOBAL",
            "sk": "COMBO#hidden-card",
            "type": "combo",
            "comboId": "hidden-card",
            "combo": "hidden-card",
            "scope": "global",
            "classes": ["ank-d-none"],
            "updatedAt": "2026-07-01T12:00:00Z",
        }

        policy_response = handler.lambda_handler(event(
            "/features/combo-catalog/action",
            {
                "action": "setDraftPolicy",
                "scope": "draft",
                "draftDomain": "zoositioweb.com.mx",
                "defaultAccess": "allow",
                "deniedCombos": ["hidden-card"],
            },
            cookie=cookie,
            csrf=csrf,
        ), None)
        read_response = handler.lambda_handler(event(
            "/features/combo-catalog/read",
            {"read": "runtimeCombos"},
        ), None)

        self.assertEqual(policy_response["statusCode"], 200)
        self.assertEqual(read_response["statusCode"], 200)
        self.assertEqual(body(read_response)["data"]["combos"], {})


if __name__ == "__main__":
    unittest.main()

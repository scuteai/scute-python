"""5. Admin users with the secret key: create, get (by id and by identifier),
update, deactivate, activate, delete; and after a delete, the fresh account a
returning user gets, their previous accounts and merging one in. All SDK
(scute.users); the sign-ins go through the HTTP helper.

Not run: users.invite sends a real magic-link email (test identities only
cover OTP codes).
"""

from __future__ import annotations

import pytest

from scute import APIError, Scute

from .support import (
    Cleanup,
    LiveAPI,
    Names,
    Policy,
    assign_role,
    delete_user_later,
    revoke_role_later,
    sign_in,
)

pytestmark = pytest.mark.live


def test_manages_a_user(scute: Scute, names: Names, cleanup: Cleanup) -> None:
    email = names.email(6)
    created = scute.users.create(email)["user"]
    user_id = str(created["id"])
    delete_user_later(scute, cleanup, user_id)
    assert created["email"] == email

    got = scute.users.get(user_id)["user"]
    assert (got["id"], got["email"], got["status"]) == (user_id, email, "active")
    found = scute.users.find_by_identifier(email)
    assert found is not None and found["id"] == user_id
    assert [u["id"] for u in scute.users.list(email=email)["users"]] == [user_id]

    attributes = {"department": "ops", "run": names.run_id}
    assert scute.users.update(user_id, authz_attributes=attributes)["user"]["authz_attributes"] == attributes
    assert scute.users.get(user_id)["user"]["authz_attributes"] == attributes

    assert scute.users.deactivate(user_id)["user"]["status"] == "inactive"
    assert scute.users.activate(user_id)["user"]["status"] == "active"

    scute.users.delete(user_id)
    with pytest.raises(APIError) as gone:
        scute.users.get(user_id)
    assert gone.value.status == 404


def test_finds_a_user_by_phone(scute: Scute, names: Names, cleanup: Cleanup) -> None:
    phone = names.phone(2)
    user_id = str(scute.users.create(phone)["user"]["id"])
    delete_user_later(scute, cleanup, user_id)
    found = scute.users.find_by_identifier(phone)
    assert found is not None and found["id"] == user_id


def test_find_by_identifier_is_none_for_nobody(scute: Scute, names: Names, cleanup: Cleanup) -> None:
    """None when nobody by that identifier uses the app, and nobody gets made."""
    email = names.email(7)
    found = scute.users.find_by_identifier(email)
    if found:
        delete_user_later(scute, cleanup, str(found["id"]))
    assert found is None, "find_by_identifier found (or made) a user for an identifier nobody uses"
    assert scute.users.list(email=email)["users"] == []
    assert scute.users.find_by_identifier(names.phone(3)) is None


def test_find_by_identifier_matches_exactly(scute: Scute, names: Names, cleanup: Cleanup) -> None:
    """The search behind it is loose (q=); only the exact email, in any case, counts."""
    exact, near = names.email(10), names.email(100)  # near-identical: the loose search answers both
    ids: dict[str, str] = {}
    for email in (exact, near):
        ids[email] = str(scute.users.create(email)["user"]["id"])
        delete_user_later(scute, cleanup, ids[email])
    found = scute.users.find_by_identifier(exact.upper())
    assert found is not None and found["id"] == ids[exact]


def test_meta_needs_declared_fields(scute: Scute, names: Names, cleanup: Cleanup) -> None:
    """user_meta keys have to be declared on the app first (user meta fields, a
    dashboard setting the app's secret can't change). Undeclared, create() still
    makes the user and reports the dropped keys in user_meta_errors (no
    exception); update() is refused."""
    key = f"live_{names.run_id}"
    created = scute.users.create(names.email(8), meta={key: "pro"})
    user_id = str(created["user"]["id"])
    delete_user_later(scute, cleanup, user_id)
    assert created.get("user_meta_errors")
    assert key not in (scute.users.get(user_id)["user"].get("meta") or {})
    with pytest.raises(APIError) as refused:
        scute.users.update(user_id, user_meta={key: "team"})
    assert refused.value.status == 422


def test_a_deleted_user_who_signs_in_again_gets_a_fresh_account(api: LiveAPI, scute: Scute, names: Names,
                                                                 cleanup: Cleanup, policy: Policy) -> None:
    """Deleted, then signed in again: a new account, the old one listed as a
    previous account and merged in (its role moves over), once."""
    email = names.email(11)
    first = sign_in(api, email)
    delete_user_later(scute, cleanup, first.user_id)
    assign_role(api, cleanup, first.user_id, policy.auditor)
    scute.users.delete(first.user_id)

    again = sign_in(api, email)
    delete_user_later(scute, cleanup, again.user_id)
    revoke_role_later(api, cleanup, again.user_id, policy.auditor)  # the role moves over below
    assert again.user_id != first.user_id
    with pytest.raises(APIError) as gone:
        scute.users.get(first.user_id)
    assert gone.value.status == 404
    target = f"{policy.invoice}:1"
    assert not scute.authz.check(user_id=again.user_id, action="read", resource=target).allowed

    previous = scute.users.previous_accounts(again.user_id)
    assert [a["id"] for a in previous] == [first.user_id]
    assert previous[0]["deleted_at"] and previous[0]["roles"] == 1 and "merged_into" not in previous[0]

    merged = scute.users.merge(again.user_id, first.user_id)
    assert (merged["user_id"], merged["merged"], merged["moved"]["roles"]) == (again.user_id, first.user_id, 1)
    held = api.ok("GET", api.apps(f"/authz/users/{again.user_id}/roles"))["roles"]
    assert [g["role"] for g in held] == [policy.auditor]
    assert scute.authz.check(user_id=again.user_id, action="read", resource=target).allowed
    assert scute.users.previous_accounts(again.user_id)[0]["merged_into"] == again.user_id

    with pytest.raises(APIError) as twice:
        scute.users.merge(again.user_id, first.user_id)
    assert (twice.value.status, twice.value.code) == (422, "already_merged")


def test_someone_deactivated_then_deleted_cant_sign_in_again(api: LiveAPI, scute: Scute, names: Names,
                                                           cleanup: Cleanup) -> None:
    """Deprovisioned (deactivated, then deleted): no fresh account, the sign-in is refused."""
    email = names.email(12)
    user_id = str(scute.users.create(email)["user"]["id"])
    delete_user_later(scute, cleanup, user_id)
    scute.users.deactivate(user_id)
    scute.users.delete(user_id)
    refused = api.call("POST", api.auth("/otps/login"), {"identifier": email}, secret=False)
    assert (refused.status, refused.error_code) == (403, "account_deactivated")
    assert scute.users.find_by_identifier(email) is None

"""5. Admin users with the secret key: create, get (by id and by identifier),
update, deactivate, activate, delete. All SDK (scute.users).

Not run: users.invite sends a real magic-link email (test identities only
cover OTP codes).
"""

from __future__ import annotations

import pytest

from scute import APIError, Scute

from .support import Cleanup, Names, delete_user_later

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

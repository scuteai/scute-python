# scute (Python)

Scute for Python: verify your users' sign-ins, manage users and sessions, and
check what they may do.

```bash
pip install git+https://github.com/scuteai/scute-python
```

Set `SCUTE_APP_ID` and `SCUTE_SECRET` (server side only). Python 3.10+.

## Authentication

Your frontend signs people in with a Scute SDK; your backend verifies the
access token it sends. Verification is local: RS256 against the app's
published keys, which are cached and re-read when they rotate. It checks the
expiry and that the token belongs to this app.

```python
from scute import Scute, InvalidToken

scute = Scute()

try:
    session = scute.tokens.verify(token)       # remote=True also asks Scute (a revoked session fails)
except InvalidToken as e:
    ...                                          # e.reason: "expired", "signature", "wrong_app", ...

session.user_id
session.impersonated                             # someone (support) is signed in as this user
session.actor                                    # who: {"kind": "backend", "email": "support@acme.com"}
```

## Users and sessions (secret key)

```python
scute.users.create("ada@example.com", meta={"plan": "pro"})
scute.users.invite("bob@example.com")
scute.users.find_by_identifier("ada@example.com")
scute.users.update(user_id, user_meta={"plan": "team"})
scute.users.deactivate(user_id)

scute.sessions.list(user_id)
scute.sessions.revoke(user_id, session_id)
scute.sessions.current_user(access_token)
scute.sessions.sign_out(access_token)
```

### Signing in as a user (support access)

This is off until the app turns it on. The session is short and never
refreshed, and its token names who is really acting.

```python
tokens = scute.users.impersonate(user_id, reason="Ticket 4411", actor={"email": "support@acme.com"}, minutes=15)
scute.users.stop_impersonating(user_id)
```

## Authorization

```python
decision = scute.authz.check(user_id=session.user_id, action="refund", resource="invoice:42",
                             context=session.authz_context())
decision.allowed          # True only for a plain allow
decision.needs_step_up    # verify first
decision.needs_approval   # a reviewer approves
```

Always pass `session.authz_context()` as the context. When someone is signed in
as the user, it makes the check refuse the permissions marked "not while
impersonating".

## Frameworks

```python
# FastAPI (pip install "scute[fastapi]")
from scute.contrib.fastapi import ScuteAuth
auth = ScuteAuth(Scute())

@app.post("/invoices/{id}/refund", dependencies=[Depends(auth.require("refund", "invoice:{id}"))])
def refund(id: str, session: Annotated[Session, Depends(auth.session)]): ...

# Flask (pip install "scute[flask]")
from scute.contrib.flask import ScuteAuth
auth = ScuteAuth(Scute())

@app.post("/invoices/<id>/refund")
@auth.permission("refund", "invoice:{id}")
def refund(id): ...  # flask.g.scute_session
```

No valid session gets a 401, and a check that isn't a plain allow gets a 403.
Checks always carry the impersonation context.

## Local decisions

```python
from scute.local import decide_locally
decide_locally(snapshot_policy, roles=["clerk"], action="approve", resource={"type": "invoice", "attributes": {"amount": 4200}})
```

This gives the same answers as Scute's engine for everything the snapshot
knows; the shared conformance vectors are part of the tests. Anything it can't
answer comes back as `"unknown"`, and then you ask the API.

## Live suite

`tests/live` runs the SDK against a real Scute API (the v2 deployment), no
mocks. It's off in the normal run and in CI (`pytest` deselects it); run it
with:

```bash
pip install -e ".[dev]"
pytest -m live
```

Credentials: an app made for this suite, with test identities on (sign-in
codes are always `424242` for `...+scute_test@example.com` and
`+1 415 555 01xx`, and nothing is sent). Make it once, on the v2 API only:

```bash
heroku run -a scute-api-v2 rake "sdk_live:setup[python]"
```

It prints three lines. Put them in `.sdk-live/python.env` next to your checkout
(outside the repo, never committed), or export them, or point
`SCUTE_LIVE_ENV_FILE` at another file:

```bash
SCUTE_LIVE_BASE_URL=...
SCUTE_LIVE_APP_ID=...
SCUTE_LIVE_SECRET=...
```

Without them every live test is skipped with one line saying so, and the run
exits 0.

What it covers, in order (one file each, `tests/live/test_01_app.py` to
`test_10_decision_log.py`):

1. App: its public data; the SDK finding the public id from the app's UUID.
2. Sign-in: email OTP and SMS OTP with test identities, then the user,
   refresh, sign out, listing and revoking sessions.
3. Tokens: local JWKS verification (a tampered, an expired and another
   audience's token refused) and `remote=True`.
4. MFA: TOTP enrollment (codes computed per RFC 6238), a sign-in that needs
   MFA finished with TOTP, backup codes, removing the method.
5. Users: create, get by id and by identifier, update, deactivate, activate,
   delete.
6. Signing in as a user: start (the `act` claim), list, stop, and a "not while
   impersonating" permission refused inside the session.
7. Authorization: policy import, role assignment, check, check-batch,
   permissions, authorized users, filter, the signed snapshot with
   `decide_locally` matching the server, access requests; and the FastAPI and
   Flask glue with real sessions.
8. Agents: a task, checks through it, a step-up through the human steps,
   properties (a secret; a signature checked against the JWKS), a budget that
   pauses the agent, suspend and resume.
9. The auth MCP server over JSON-RPC with an agent key, then the backend's
   conversation lookup and check.
10. The decision log: rows for the checks above.

Where this SDK has no API (the sign-in itself, MFA, policy and roles, filter,
the snapshot, access requests, agents and their tasks, properties, the auth
MCP, the decision log), the suite calls the HTTP API directly with httpx and
says so in the test. There's no Python agent harness yet.

Each run is named `live-<runid>` (users, roles, resources, agents,
properties) and deletes what it made at the end, also when tests fail. It
keeps sign-ins to five per run (the API throttles them) and never prints the
secret, tokens or codes other than 424242.

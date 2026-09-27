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

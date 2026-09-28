# scute (Python)

Scute for Python: verify your users' sign-ins, manage users and sessions, and
check what they may do.

```bash
pip install git+https://github.com/scuteai/scute-python
```

Not on PyPI: the `scute` name there belongs to an unrelated package, so always install from GitHub. Pin a commit with `@<sha>` on the URL.

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
scute.users.find_by_identifier("ada@example.com")  # exact email (any case) or phone (as digits); None if nobody
scute.users.update(user_id, user_meta={"plan": "team"})
scute.users.deactivate(user_id)

scute.users.previous_accounts(user_id)              # earlier, deleted accounts of the same person
scute.users.merge(user_id, from_id)                # move one's roles, passkeys and MFA over (once)

scute.sessions.list(user_id)                       # the secret key alone is enough, no user session
scute.sessions.revoke(user_id, session_id)         # ends it at once
scute.sessions.current_user(access_token)
scute.sessions.sign_out(access_token)
```

Someone deleted who signs in again gets a fresh account (a new id); their
earlier account stays deleted, with its history. `previous_accounts` lists the
earlier accounts and `merge` brings one into the live account (for meta and
attributes the live account wins). Someone deactivated and then deleted can't
sign in again (403, `account_deactivated`) until you bring them back.

`meta` and `user_meta` keys are the user meta fields declared for the app (in
the dashboard): others are left out on create (listed in `user_meta_errors`)
and refused on update.

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
# FastAPI (pip install "scute[fastapi] @ git+https://github.com/scuteai/scute-python")
from scute.contrib.fastapi import ScuteAuth
auth = ScuteAuth(Scute())

@app.post("/invoices/{id}/refund", dependencies=[Depends(auth.require("refund", "invoice:{id}"))])
def refund(id: str, session: Annotated[Session, Depends(auth.session)]): ...

# Flask (pip install "scute[flask] @ git+https://github.com/scuteai/scute-python")
from scute.contrib.flask import ScuteAuth
auth = ScuteAuth(Scute())

@app.post("/invoices/<id>/refund")
@auth.permission("refund", "invoice:{id}")
def refund(id): ...  # flask.g.scute_session
```

No valid session gets a 401, and a check that isn't a plain allow gets a 403.
Checks always carry the impersonation context.

## Agents

Register the agents you build with roles (their ceiling), then run each job
as a short-lived task. Every tool call is checked against the agent's roles,
the person it works for and the task, all three.

```python
scute.agents.create("support-bot", roles=["support"], settings={"budget": {"max_actions": 50}})
scute.agents.suspend("support-bot")        # the kill switch: every open task ends
```

### The harness

```python
from scute.harness import Harness, guards

harness = Harness(
    agent="support-bot",
    guards=[
        guards.permissions(),                          # Scute's engine: the agent, the person, the task
        guards.approval(when={"tier": "high"}),         # the person confirms risky calls
        guards.grounding(),                             # ids and amounts come from the person or a tool
        guards.args({"refund_invoice": {"amount": {"max": 500}}}),
        guards.budget(calls=20, per_hour={"high": 5}),
        guards.content(pii=["card", "ssn"]),
    ],
    tools={"refund_invoice": {"tier": "high"}},
    store=my_redis_store,                              # runs resume across requests and processes
)

run = harness.run(id=conversation_id, acts_for=user_id, actions=["invoice:read", "invoice:refund"])

verdict = run.check("refund_invoice", {"invoice_id": "INV-1", "amount": 90}, messages=transcript)
if verdict.runs:
    result = run.after("refund_invoice", verdict.args, billing.refund(**verdict.args))
else:
    result = verdict.message                        # for the model: what to do next
    tell_the_person(verdict.say)                    # for the person, when there's a line

@run.wrap("refund_invoice")                         # or guard a function: the result, or the message
def refund(invoice_id: str, amount: float) -> str: ...
```

Guards answer `proceed`, `transform`, `approve`, `verify`, `guide`,
`redirect` or `deny`; the strictest enforced answer wins, and a guard that
raises counts as deny. Each guard runs in `enforce`, `monitor` (calls
`on_alert`, never blocks) or `observe` mode; `on_decision` sees every
decision. Your own: `guards.define("no-weekend-refunds", lambda call: ...)`.

Tool names map to permissions: `refund_invoice` needs `invoice:refund` on the
invoice named by `invoice_id` (or `invoiceId`, or `id`). The arguments reach
the engine as `context.args`; the object's attributes come from what Scute
stores, which the model can't override. Override per tool:
`tools={"send_money": {"permission": "payment:create", "key": "to"}, "get_weather": False}`.

A run is one job: a task (its token is minted on first use and never shown to
the model), its session, and what the guards remember. Checks within a run
go one at a time, so budgets hold under parallel tool calls. A task Scute
ends (revoked, completed, the agent suspended or over its budget) closes the
run for good. `run.complete()` or `run.revoke()` ends it. An agent process
without the secret runs on a task token your backend minted:
`harness.run(token=task["token"])` after `scute.agents.start_task(...)`.

People in the loop, all with the task token:

- Verify: `run.start_verification(verdict=verdict, method="email_otp")` sends a
  code (or `sms_otp`, `totp`, `entra_push`), `run.submit_code(code)` passes on
  what the person read out, `run.verification_status()` checks a push. The next
  check of that permission goes through.
- Let the model do it: `run.human_tools()` gives it `scute_verify_person`,
  `scute_submit_code`, `scute_check_verification`, `scute_approval_status` and
  `scute_whoami`, as callables with JSON Schema parameters for any framework.
  Every answer has a `say` line the agent can speak as is.
- Confirm: `run.confirm(tool, args)` when the person confirmed a call in your UI.
- Reviewer approval: filed as an access request for the exact call (its
  arguments go with it); `verdict.say` tells the person, `run.approval_status(id)`
  checks, and only that same call goes through once approved.

Inside a tool: `run.property("stripe")` reads one of the app's secrets (use it,
never return it), and `run.sign("mandates", claims={...})` signs with one of
its key pairs (public keys at `/v1/auth/:app_id/properties/:name/jwks.json`).
`run.whoami()` says who the agent works for and what the task allows.

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
   pauses the agent, suspend and resume; and the same through `scute.harness`
   (`test_08_harness.py`), including a reviewer's approval and a run on a
   token minted by the backend.
9. The auth MCP server over JSON-RPC with an agent key, then the backend's
   conversation lookup and check.
10. The decision log: rows for the checks above.

Where this SDK has no API (the sign-in itself, MFA, policy and roles, filter,
the snapshot, access requests, managing properties, the auth MCP, the decision
log), the suite calls the HTTP API directly with httpx and says so in the
test. `test_08_harness.py` runs `scute.harness` for real: proceed, a deny
outside the task, a step-up with 424242, a reviewer's approval, properties,
and a budget that closes the run.

API bugs the suite has confirmed are marked `xfail(strict=True)` with the
finding as the reason: the run stays green, and a fix shows up as an
unexpected pass to clean up.

Each run is named `live-<runid>` (users, roles, resources, agents,
properties) and deletes what it made at the end, also when tests fail. It
keeps sign-ins to seven per run (the API throttles them) and never prints the
secret, tokens or codes other than 424242.

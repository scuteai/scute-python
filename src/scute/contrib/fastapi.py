"""FastAPI glue.

    from scute import Scute
    from scute.contrib.fastapi import ScuteAuth

    auth = ScuteAuth(Scute())

    @app.post("/invoices/{id}/refund")
    def refund(id: str, session: Annotated[Session, Depends(auth.session)],
               _: Annotated[Decision, Depends(auth.require("refund", "invoice:{id}"))]):
        ...

401 without a valid session, 403 when the check isn't a plain allow (the
decision rides on the error detail). Checks carry the impersonation context.

`Depends(auth.client)` is the Scute client for the request: its secret-key
calls send the person's address (request.client.host) as X-Scute-Client-IP,
and `auth.require` uses it. Behind a proxy, run uvicorn with --proxy-headers
and --forwarded-allow-ips set to your proxy so that is the person's address.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, Request

from .._client_ip import clean_client_ip
from ..authz import Decision
from ..client import Scute
from ..errors import InvalidToken
from ..tokens import Session
from ._token import access_token


class ScuteAuth:
    def __init__(self, scute: Scute, *, remote: bool = False) -> None:
        self.scute = scute
        self.remote = remote

    def client(self, request: Request) -> Scute:
        """A dependency: the client for this request, sending
        request.client.host when that is one IP address."""
        ip = clean_client_ip(request.client.host if request.client else None)
        return self.scute.with_client_ip(ip) if ip else self.scute

    def session(self, request: Request) -> Session:
        ids = [self.scute.app_id]
        if any(k.startswith("sc-access-token__") for k in request.cookies):
            ids.append(self.scute.tokens.public_app_id)
        token = access_token(request.headers.get, request.cookies, ids)
        try:
            session = self.scute.tokens.verify(token, remote=self.remote)
        except InvalidToken as e:
            raise HTTPException(status_code=401, detail={"error": str(e), "reason": e.reason}) from e
        request.state.scute_session = session
        return session

    def require(self, action: str, resource: str | None = None,
                context: Callable[[Request], dict[str, Any]] | None = None) -> Callable[[Request], Decision]:
        """A dependency: the signed-in user may do `action` on `resource`
        ("invoice:{id}" fills in path parameters)."""

        def dependency(request: Request) -> Decision:
            session = getattr(request.state, "scute_session", None) or self.session(request)
            target = resource.format(**request.path_params) if resource else None
            extra = context(request) if context else {}
            decision = self.client(request).authz.check(user_id=session.user_id, action=action, resource=target,
                                                        context={**extra, **session.authz_context()} or None)
            if not decision.allowed:
                raise HTTPException(status_code=403, detail={"error": decision.explanation or "Not allowed",
                                                             "decision": decision.raw})
            return decision

        return dependency

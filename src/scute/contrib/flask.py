"""Flask glue.

    from scute import Scute
    from scute.contrib.flask import ScuteAuth

    auth = ScuteAuth(Scute())

    @app.post("/invoices/<id>/refund")
    @auth.required
    @auth.permission("refund", "invoice:{id}")
    def refund(id): ...
        # flask.g.scute_session

401 without a valid session, 403 when the check isn't a plain allow.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from flask import g, jsonify, request

from ..client import Scute
from ..errors import InvalidToken
from ._token import access_token

F = TypeVar("F", bound=Callable[..., Any])


class ScuteAuth:
    def __init__(self, scute: Scute, *, remote: bool = False) -> None:
        self.scute = scute
        self.remote = remote

    def _session(self) -> Any:
        ids = [self.scute.app_id]
        if any(k.startswith("sc-access-token__") for k in request.cookies):
            ids.append(self.scute.tokens.public_app_id)
        token = access_token(request.headers.get, request.cookies, ids)
        g.scute_session = self.scute.tokens.verify(token, remote=self.remote)
        return g.scute_session

    def required(self, view: F) -> F:
        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                self._session()
            except InvalidToken as e:
                return jsonify(error=str(e), reason=e.reason), 401
            return view(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    def permission(self, action: str, resource: str | None = None) -> Callable[[F], F]:
        def decorate(view: F) -> F:
            @functools.wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                session = getattr(g, "scute_session", None)
                if session is None:
                    try:
                        session = self._session()
                    except InvalidToken as e:
                        return jsonify(error=str(e), reason=e.reason), 401
                target = resource.format(**kwargs) if resource else None
                decision = self.scute.authz.check(user_id=session.user_id, action=action, resource=target,
                                                  context=session.authz_context() or None)
                if not decision.allowed:
                    return jsonify(error=decision.explanation or "Not allowed", decision=decision.raw), 403
                g.scute_decision = decision
                return view(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorate

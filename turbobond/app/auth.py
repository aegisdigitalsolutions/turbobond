"""Sign-in for the control panel.

The first sign-in claims the account: whatever password is submitted becomes the
Argon2id-hashed credential for every subsequent sign-in. That keeps first-run
setup to a single screen without ever shipping a default password.

Sessions are signed cookies with a server-side revocation set, so signing out
actually invalidates the session rather than just dropping the cookie.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from turbobond.config import AppConfig, save_config
from turbobond.errors import AuthError
from turbobond.logging_setup import get_logger
from turbobond.util.crypto import constant_time_eq, hash_password, verify_password

log = get_logger("app.auth")

SESSION_COOKIE = "turbobond_session"
CSRF_HEADER = "X-TurboBond-CSRF"

# Brute-force protection.
MAX_FAILURES = 8
LOCKOUT_S = 300.0


@dataclass
class Session:
    sid: str
    username: str
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    remote: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "created": self.created,
            "last_seen": self.last_seen,
            "age_s": round(time.time() - self.created, 1),
            "remote": self.remote,
        }


class AuthManager:
    """Password verification and session lifecycle."""

    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self._serializer = URLSafeTimedSerializer(cfg.auth.ensure_secret(), salt="turbobond-session")
        self._sessions: dict[str, Session] = {}
        self._failures: dict[str, list[float]] = {}

    # ------------------------------------------------------------ enrolment

    @property
    def enrolled(self) -> bool:
        """Whether a password has been set yet."""

        return bool(self.cfg.auth.password_hash)

    def _enrol(self, username: str, password: str) -> None:
        if len(password) < 8:
            raise AuthError(
                "choose a password of at least 8 characters",
                remedy="This password protects a gateway that can reconfigure your network.",
            )
        self.cfg.auth.username = username or self.cfg.auth.username
        self.cfg.auth.password_hash = hash_password(password)
        try:
            save_config(self.cfg)
        except Exception as exc:
            log.warning("could not persist credentials: %s", exc)
        log.info("account '%s' created on first sign-in", self.cfg.auth.username)

    # -------------------------------------------------------------- lockout

    def _locked_out(self, key: str) -> float:
        """Seconds remaining on a lockout, or 0."""

        now = time.time()
        attempts = [t for t in self._failures.get(key, []) if now - t < LOCKOUT_S]
        self._failures[key] = attempts
        if len(attempts) >= MAX_FAILURES:
            return LOCKOUT_S - (now - attempts[0])
        return 0.0

    def _record_failure(self, key: str) -> None:
        self._failures.setdefault(key, []).append(time.time())

    # --------------------------------------------------------------- signin

    def sign_in(self, username: str, password: str, *, remote: str = "") -> Session:
        """Verify credentials and open a session."""

        key = remote or "unknown"
        remaining = self._locked_out(key)
        if remaining > 0:
            raise AuthError(
                f"too many failed sign-in attempts; try again in {int(remaining)} seconds",
            )

        if not password:
            raise AuthError("a password is required")

        if not self.enrolled:
            self._enrol(username, password)
        else:
            expected_user = self.cfg.auth.username
            if not constant_time_eq(username or expected_user, expected_user) or not verify_password(
                password, self.cfg.auth.password_hash
            ):
                self._record_failure(key)
                log.warning("failed sign-in for '%s' from %s", username, remote or "unknown")
                raise AuthError("that username or password is not correct")

        self._failures.pop(key, None)
        session = Session(sid=secrets.token_urlsafe(32), username=self.cfg.auth.username, remote=remote)
        self._sessions[session.sid] = session
        log.info("'%s' signed in from %s", session.username, remote or "unknown")
        return session

    def issue_cookie(self, session: Session) -> str:
        return self._serializer.dumps({"sid": session.sid, "u": session.username})

    def resolve(self, token: str | None) -> Session | None:
        """Turn a cookie back into a live session."""

        if not token:
            return None
        try:
            data = self._serializer.loads(token, max_age=self.cfg.auth.session_ttl_s)
        except SignatureExpired:
            log.debug("session cookie expired")
            return None
        except BadSignature:
            log.warning("rejected a session cookie with an invalid signature")
            return None
        if not isinstance(data, dict):
            return None
        session = self._sessions.get(str(data.get("sid", "")))
        if session is None:
            return None
        if time.time() - session.created > self.cfg.auth.session_ttl_s:
            self._sessions.pop(session.sid, None)
            return None
        session.last_seen = time.time()
        return session

    def sign_out(self, session: Session | None) -> None:
        if session is not None:
            self._sessions.pop(session.sid, None)
            log.info("'%s' signed out", session.username)

    def sign_out_all(self) -> int:
        count = len(self._sessions)
        self._sessions.clear()
        return count

    def check_csrf(self, session: Session, token: str | None) -> None:
        if not token or not constant_time_eq(token, session.csrf):
            raise AuthError("this request is missing a valid CSRF token")

    def sessions(self) -> list[dict[str, Any]]:
        return [s.as_dict() for s in self._sessions.values()]

    def change_password(self, session: Session, current: str, new: str) -> None:
        if not verify_password(current, self.cfg.auth.password_hash):
            raise AuthError("the current password is not correct")
        if len(new) < 8:
            raise AuthError("choose a new password of at least 8 characters")
        self.cfg.auth.password_hash = hash_password(new)
        save_config(self.cfg)
        # Every other session is invalidated by a password change.
        keep = self._sessions.get(session.sid)
        self._sessions.clear()
        if keep is not None:
            self._sessions[keep.sid] = keep
        log.info("password changed for '%s'", session.username)

"""Exception hierarchy shared by every turbobond subsystem."""

from __future__ import annotations


class TurboBondError(Exception):
    """Base class for all turbobond failures."""

    #: Short machine-readable code surfaced to the API/UI.
    code = "turbobond_error"

    def __init__(self, message: str, *, remedy: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remedy = remedy

    def as_dict(self) -> dict[str, str | None]:
        return {"code": self.code, "message": self.message, "remedy": self.remedy}


class ConfigError(TurboBondError):
    code = "config_error"


class DependencyError(TurboBondError):
    code = "dependency_error"


class PrivilegeError(TurboBondError):
    code = "privilege_error"


class RouterError(TurboBondError):
    code = "router_error"


class RouterAuthError(RouterError):
    code = "router_auth_error"


class RouterUnsupportedError(RouterError):
    """The router answered, but does not expose the field/endpoint we need."""

    code = "router_unsupported"


class LinkError(TurboBondError):
    code = "link_error"


class BondError(TurboBondError):
    code = "bond_error"


class TransportError(TurboBondError):
    code = "transport_error"


class FirewallError(TurboBondError):
    code = "firewall_error"


class ActivationError(TurboBondError):
    code = "activation_error"


class AuthError(TurboBondError):
    code = "auth_error"

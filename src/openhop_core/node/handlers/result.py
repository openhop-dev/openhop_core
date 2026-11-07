"""Shared result type returned by receive handlers."""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class HandlerResult:
    """Uniform outcome returned by every receive handler.

    A single result type lets callers — the local node, the companion bridge,
    and the repeater router — make one consistent forwarding decision instead of
    interpreting handler-specific return values. New fields can be added here
    without touching call sites that only care about ``authenticated``.

    Attributes:
        authenticated: True once the packet was MAC-verified/decrypted for a
            concrete local identity, so the caller must consume it (stop
            forwarding) even when there is no reply. False means no local
            identity proved ownership — e.g. a one-byte prefix collision — and
            the caller must leave the packet available to the forwarding engine.
        response: An optional packet to transmit in reply (e.g. a request
            response or path return); None when no reply is warranted.
        response_claimed: A pending request already claimed this response.
            PATH dispatch must not interpret it again as a login reply.
    """

    authenticated: bool
    response: Optional[Any] = None
    response_claimed: bool = False

    @classmethod
    def not_for_us(cls) -> "HandlerResult":
        """No local identity authenticated the packet; leave it for forwarding."""
        return cls(authenticated=False)

    @classmethod
    def consumed(
        cls, response: Optional[Any] = None, *, response_claimed: bool = False
    ) -> "HandlerResult":
        """Authenticated for a local identity; optionally reply with ``response``."""
        return cls(authenticated=True, response=response, response_claimed=response_claimed)

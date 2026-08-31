"""Helpers for invoking sync or async user callbacks."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Optional

# Contract for an ACK-received listener/callback: given a received ACK CRC, it reports whether
# that CRC matched (was consumed by) one of THIS node's own pending sends.
#   truthy  -> the ACK is one of mine; the ack handler marks the packet do-not-retransmit so a
#              client repeater does not re-flood an ACK addressed to itself (firmware
#              BaseChatMesh::onAckRecv / Mesh::onRecvPacket).
#   False / None -> not one of mine (take no do-not-retransmit action).
# The callback may be synchronous or asynchronous; a ``None``-returning callback stays
# backward-compatible with the older notify-only contract.
AckReceivedCallback = Callable[[int], "Awaitable[Optional[bool]] | Optional[bool]"]


async def invoke_maybe_awaitable(callback: Callable[..., Any], *args: Any) -> Any:
    """Call ``callback(*args)`` and await the result when it is awaitable.

    True ``async def`` callbacks, sync wrappers that return a coroutine or
    other awaitable, and callable objects with ``async def __call__`` are
    all awaited inline. Plain sync callbacks that return ``None`` (or any
    non-awaitable) complete without scheduling. The callback's result is
    returned so callers can act on it.
    """
    result = callback(*args)
    if inspect.isawaitable(result):
        return await result
    return result

"""Path packet handler for mesh network routing."""

from typing import Callable

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_PATH
from .result import HandlerResult


class PathHandler:
    """Handler for PATH packets (payload type 0x08) - "Returned path" packets.

    According to the official documentation, PATH packets are used for returning
    responses through the mesh network along discovered routing paths.

    Official Packet Structure:
    - Header [1B]: Route type (0-1) + Payload type (2-5) + Version (6-7)
    - Path Length [1B]: Length of the path field
    - Path [up to 64B]: Routing path data (if applicable)
    - Payload [up to 184B]: The actual data being transmitted

    For PATH packets, the payload typically contains:
    - [1B] dest_hash: Destination node hash
    - [1B] src_hash: Source node hash
    - [2B] MAC: Message Authentication Code (for payload version 0x00)
    - [NB] encrypted_data: Contains ACK or other response data
    """

    def __init__(
        self,
        log_fn: Callable[[str], None],
        ack_handler=None,
        protocol_response_handler=None,
        login_response_handler=None,
    ):
        self._log = log_fn
        self._ack_handler = ack_handler
        self._protocol_response_handler = protocol_response_handler
        self._login_response_handler = login_response_handler

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_PATH

    def set_ack_handler(self, ack_handler):
        """Set the ACK handler for processing bundled/encrypted ACKs in PATH packets."""
        self._ack_handler = ack_handler

    async def __call__(self, pkt: Packet) -> HandlerResult:
        """Handle PATH and aggregate authenticated sub-handler results."""
        authenticated = False
        try:
            # First, check if this PATH packet contains protocol responses
            if self._protocol_response_handler:
                result = await self._protocol_response_handler(pkt)
                authenticated = authenticated or (
                    isinstance(result, HandlerResult) and result.authenticated
                )

            # Then, check if this PATH packet contains login responses
            if self._login_response_handler:
                result = await self._login_response_handler(pkt)
                authenticated = authenticated or (
                    isinstance(result, HandlerResult) and result.authenticated
                )

            # Then, check if this PATH packet contains ACKs and delegate to ACK handler
            if self._ack_handler:
                ack_crc = await self._ack_handler.process_path_ack_variants(pkt)
                if ack_crc is not None:
                    # A successfully MAC-verified/decrypted PATH proves the packet
                    # belongs to this identity, so it is authenticated regardless
                    # of whether anything is awaiting the embedded CRC — firmware
                    # Mesh::onRecvPacket sets `found` (and marks do-not-retransmit)
                    # on MACThenDecrypt success alone; whether the CRC confirms a
                    # particular send is processAck's separate, app-level decision.
                    # HandlerResult.authenticated carries the consume/no-forward
                    # decision to both the dispatcher and the companion bridge.
                    authenticated = True
                    await self._ack_handler._notify_ack_received(ack_crc)

            # Optional PATH packet analysis if analyzer is available
            try:
                if (
                    hasattr(self, "_dispatcher")
                    and hasattr(self._dispatcher, "packet_analysis_callback")
                    and self._dispatcher.packet_analysis_callback
                ):
                    self._dispatcher.packet_analysis_callback(pkt)
            except Exception as e:
                self._log(f"PATH packet analysis failed: {e}")

            # Single summary line for PATH packet
            try:
                payload = pkt.get_payload()
                hop_count = pkt.get_path_hash_count()
                if len(payload) >= 2:
                    dest_hash = payload[0]
                    src_hash = payload[1]
                    self._log(
                        f"PATH packet: hop_count={hop_count}, "
                        f"dest=0x{dest_hash:02X}, src=0x{src_hash:02X}, payload_len={len(payload)}"
                    )
                else:
                    self._log("PATH packet: minimal payload")
            except Exception as e:
                self._log(f"Error extracting PATH information: {e}")

        except Exception as e:
            self._log(f"Error in PATH handler: {e}")
            import traceback

            self._log(traceback.format_exc())

        return HandlerResult.consumed() if authenticated else HandlerResult.not_for_us()

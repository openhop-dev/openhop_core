"""fabric.origin_tx="all": locally originated packets egress on every radio.

Forwards are steered by tx_mode (e.g. bridge: RX radio -> the other radio),
but a locally originated packet has no RX side, so in a bridge topology it
would leave on the default radio only and never cross the link. With
origin_tx="all" the Dispatcher fans origins out to every registered radio,
sequentially in registration order (send_all awaits each radio's TX-done
before the next starts, so transmissions are serialised, never simultaneous).
"""

from __future__ import annotations

import pytest
from openhop_core.node.dispatcher import Dispatcher
from openhop_core.protocol import Packet
from openhop_core.protocol.constants import PAYLOAD_TYPE_ADVERT
from openhop_core.protocol.packet_filter import PacketFilter
from openhop_core.rf_fabric import FabricRadio, RFFabric


class _MockRadio:
    def __init__(self, name: str = "r", order_log=None):
        self.name = name
        self.rx_callback = None
        self.sent = []
        self._order_log = order_log

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes):
        self.sent.append(data)
        if self._order_log is not None:
            self._order_log.append(self.name)
        return {"radio": self.name}

    def get_last_rssi(self):
        return -80

    def get_last_snr(self):
        return 7.5


class _FailingRadio(_MockRadio):
    async def send(self, data: bytes):
        raise RuntimeError("TX path down")


class _NoConfirmRadio(_MockRadio):
    async def send(self, data: bytes):
        self.sent.append(data)
        return None


def _origin_advert() -> Packet:
    pkt = Packet()
    pkt.header = PAYLOAD_TYPE_ADVERT << 2
    pkt.payload = bytearray(b"origin-tx")
    pkt.payload_len = len(pkt.payload)
    pkt.path_len = 0
    return pkt


class TestOriginTxKnob:
    def test_default_and_validation(self):
        fabric = RFFabric()
        assert fabric.origin_tx == "default"
        fabric.set_origin_tx("all")
        assert fabric.origin_tx == "all"
        fabric.set_origin_tx(" Default ")
        assert fabric.origin_tx == "default"
        with pytest.raises(ValueError):
            fabric.set_origin_tx("broadcast")


class TestSendAll:
    @pytest.mark.asyncio
    async def test_sequential_fan_out_in_registration_order(self):
        order = []
        a = _MockRadio("a", order_log=order)
        b = _MockRadio("b", order_log=order)
        fabric = RFFabric()
        fabric.register_radio(a, radio_id="ra")
        fabric.register_radio(b, radio_id="rb")

        meta = await fabric.send_all(b"fan-out")

        assert a.sent == [b"fan-out"]
        assert b.sent == [b"fan-out"]
        assert order == ["a", "b"]
        # First success supplies the metadata; fan-out is marked explicitly.
        assert meta["radio"] == "a"
        assert meta["radio_id"] == "all"
        assert meta["radio_ids"] == ["ra", "rb"]

    @pytest.mark.asyncio
    async def test_one_radio_failing_does_not_block_the_rest(self):
        a = _FailingRadio("a")
        b = _MockRadio("b")
        fabric = RFFabric()
        fabric.register_radio(a, radio_id="ra")
        fabric.register_radio(b, radio_id="rb")

        meta = await fabric.send_all(b"survivor")

        assert b.sent == [b"survivor"]
        assert meta["radio"] == "b"
        assert meta["radio_id"] == "all"
        assert meta["radio_ids"] == ["rb"]

    @pytest.mark.asyncio
    async def test_all_radios_failing_reports_tx_failure(self):
        fabric = RFFabric()
        fabric.register_radio(_FailingRadio("a"), radio_id="ra")
        fabric.register_radio(_NoConfirmRadio("b"), radio_id="rb")

        assert await fabric.send_all(b"nope") is None


class TestDispatcherOriginFanOut:
    @pytest.mark.asyncio
    async def test_origin_fans_out_to_every_radio(self):
        a = _MockRadio("a")
        b = _MockRadio("b")
        fr = FabricRadio(radios=[(a, "ra"), (b, "rb")], default_radio_id="ra")
        fr.fabric.set_origin_tx("all")
        d = Dispatcher(radio=fr, packet_filter=PacketFilter())

        pkt = _origin_advert()
        ok = await d.send_packet(pkt, wait_for_ack=False)

        assert ok is True
        raw = pkt.write_to()
        assert a.sent == [raw]
        assert b.sent == [raw]
        assert pkt._tx_metadata["radio_id"] == "all"
        assert pkt._tx_metadata["radio_ids"] == ["ra", "rb"]

    @pytest.mark.asyncio
    async def test_forwarded_packet_does_not_fan_out(self):
        a = _MockRadio("a")
        b = _MockRadio("b")
        fr = FabricRadio(radios=[(a, "ra"), (b, "rb")], default_radio_id="ra")
        fr.fabric.set_origin_tx("all")
        d = Dispatcher(radio=fr, packet_filter=PacketFilter())

        pkt = _origin_advert()
        pkt._rx_radio_id = "ra"  # forwards are stamped on RX
        ok = await d.send_packet(pkt, wait_for_ack=False)

        assert ok is True
        assert a.sent == [pkt.write_to()]
        assert b.sent == []

    @pytest.mark.asyncio
    async def test_explicit_radio_id_wins_over_fan_out(self):
        a = _MockRadio("a")
        b = _MockRadio("b")
        fr = FabricRadio(radios=[(a, "ra"), (b, "rb")], default_radio_id="ra")
        fr.fabric.set_origin_tx("all")
        d = Dispatcher(radio=fr, packet_filter=PacketFilter())

        pkt = _origin_advert()
        ok = await d.send_packet(pkt, wait_for_ack=False, radio_id="rb")

        assert ok is True
        assert a.sent == []
        assert b.sent == [pkt.write_to()]

    @pytest.mark.asyncio
    async def test_origin_tx_default_keeps_single_radio_egress(self):
        a = _MockRadio("a")
        b = _MockRadio("b")
        fr = FabricRadio(radios=[(a, "ra"), (b, "rb")], default_radio_id="ra")
        d = Dispatcher(radio=fr, packet_filter=PacketFilter())

        pkt = _origin_advert()
        ok = await d.send_packet(pkt, wait_for_ack=False)

        assert ok is True
        assert a.sent == [pkt.write_to()]
        assert b.sent == []

    @pytest.mark.asyncio
    async def test_single_radio_fabric_ignores_fan_out(self):
        a = _MockRadio("a")
        fr = FabricRadio(radios=[(a, "ra")], default_radio_id="ra")
        fr.fabric.set_origin_tx("all")
        d = Dispatcher(radio=fr, packet_filter=PacketFilter())

        pkt = _origin_advert()
        ok = await d.send_packet(pkt, wait_for_ack=False)

        assert ok is True
        assert a.sent == [pkt.write_to()]

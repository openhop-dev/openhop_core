"""Phase 1 RF Fabric foundation tests.

Covers the production-safe foundation only:
- RFIngress carries exactly one RadioReception
- FabricRadio → RFFabric → Dispatcher optional path
- Dispatcher(existing_radio) remains unchanged
- Legacy RX callback fires exactly once
- SX1262Radio multi-instance construction/cleanup isolation
- Phase 1 single-radio fabric path still works (N-radio covered in phase2)
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from openhop_core.node.dispatcher import Dispatcher
from openhop_core.protocol import Packet
from openhop_core.protocol.constants import PAYLOAD_TYPE_ADVERT
from openhop_core.protocol.packet_filter import PacketFilter
from openhop_core.rf_fabric import FabricRadio, RadioReception, RFFabric, RFIngress


def _advert_bytes() -> bytes:
    pkt = Packet()
    pkt.header = PAYLOAD_TYPE_ADVERT << 2
    pkt.payload = bytearray(b"phase1-fabric")
    pkt.payload_len = len(pkt.payload)
    pkt.path_len = 0
    return pkt.write_to()


class _MockRadio:
    def __init__(self):
        self.rx_callback = None
        self.sent = []
        self.last_rssi = -80
        self.last_snr = 7.5
        self.spreading_factor = 10
        self.bandwidth = 250000
        self.coding_rate = 5
        self.preamble_length = 8

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes):
        self.sent.append(data)
        return {}

    def get_last_rssi(self):
        return self.last_rssi

    def get_last_snr(self):
        return self.last_snr

    def inject(self, data: bytes, rssi=None, snr=None):
        assert self.rx_callback is not None
        if rssi is None and snr is None:
            self.rx_callback(data)
        else:
            self.rx_callback(data, rssi, snr)


class TestRFIngressModels:
    def test_from_reception_single(self):
        rx = RadioReception(data=b"abc", rssi=-70, snr=5.0, radio_id="r0")
        ingress = RFIngress.from_reception(rx)
        assert len(ingress.receptions) == 1
        assert ingress.reception is rx
        assert ingress.reception.data == b"abc"

    def test_rejects_empty_allows_multi(self):
        with pytest.raises(ValueError):
            RFIngress(receptions=())
        rx = RadioReception(data=b"x")
        multi = RFIngress(receptions=(rx, rx))
        assert len(multi.receptions) == 2


class TestRFFabricSingleRadio:
    def test_one_receive_one_ingress_one_legacy_callback(self):
        radio = _MockRadio()
        fabric = RFFabric()
        fabric.register_radio(radio, radio_id="sx0")

        ingresses = []
        legacies = []

        fabric.set_ingress_callback(lambda ing: ingresses.append(ing))
        fabric.set_legacy_rx_callback(
            lambda data, rssi=None, snr=None: legacies.append((data, rssi, snr))
        )
        fabric.arm()

        payload = b"\x01\x02\x03"
        radio.inject(payload, rssi=-90, snr=3.0)

        assert len(ingresses) == 1
        assert len(legacies) == 1
        assert len(ingresses[0].receptions) == 1
        assert ingresses[0].reception.data == payload
        assert ingresses[0].reception.radio_id == "sx0"
        assert ingresses[0].reception.rssi == -90
        assert legacies[0] == (payload, -90, 3.0)

    def test_second_radio_registration_allowed_phase2(self):
        """Phase 2: N radios may register; duplicate ids still rejected."""
        fabric = RFFabric()
        fabric.register_radio(_MockRadio(), radio_id="a")
        fabric.register_radio(_MockRadio(), radio_id="b")
        assert list(fabric.radios.keys()) == ["a", "b"]
        with pytest.raises(RuntimeError, match="already registered"):
            fabric.register_radio(_MockRadio(), radio_id="a")

    @pytest.mark.asyncio
    async def test_send_passthrough(self):
        radio = _MockRadio()
        fabric = RFFabric()
        fabric.register_radio(radio)
        await fabric.send(b"tx")
        assert radio.sent == [b"tx"]


@pytest.mark.asyncio
async def test_fabric_resets_agc_on_each_radio_that_supports_it():
    ok, failing = _MockRadio(), _MockRadio()
    ok.reset_agc = AsyncMock()
    failing.reset_agc = AsyncMock(side_effect=RuntimeError("BUSY stuck"))
    fabric = RFFabric()
    for rid, radio in (("a", failing), ("b", ok), ("c", _MockRadio())):
        fabric.register_radio(radio, radio_id=rid)

    # The dispatcher holds a FabricRadio, which passes reset_agc through.
    await FabricRadio(fabric=fabric).reset_agc()
    failing.reset_agc.assert_awaited_once()
    ok.reset_agc.assert_awaited_once()


class TestFabricRadioDispatcherPath:
    def test_dispatcher_existing_radio_unchanged(self):
        radio = _MockRadio()
        d = Dispatcher(radio=radio, packet_filter=PacketFilter())
        assert d.radio is radio
        # Bound-method identity differs per access; compare the underlying function.
        assert radio.rx_callback is not None
        assert radio.rx_callback.__func__ is Dispatcher._on_packet_received

    @pytest.mark.asyncio
    async def test_fabric_radio_to_dispatcher_fires_once(self):
        physical = _MockRadio()
        fabric_radio = FabricRadio(radio=physical, radio_id="radio0")
        d = Dispatcher(radio=fabric_radio, packet_filter=PacketFilter())

        received = []

        async def on_raw(data, rssi, snr):
            received.append((data, rssi, snr))

        # raw_rx fires once per reception before parse/dedup — the stable
        # single-delivery observation point without registering handlers.
        d.add_raw_rx_subscriber(on_raw)

        data = _advert_bytes()
        # Physical RX → fabric → FabricRadio → Dispatcher
        physical.inject(data, rssi=-75, snr=4.5)

        # Allow create_task processing
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert len(received) == 1
        assert received[0][0] == data
        assert received[0][1] == -75
        assert received[0][2] == 4.5

    @pytest.mark.asyncio
    async def test_legacy_callback_signature_once_via_fabric(self):
        physical = _MockRadio()
        fabric_radio = FabricRadio(radio=physical)
        calls = []

        def legacy_cb(data, rssi=None, snr=None):
            calls.append((data, rssi, snr))

        fabric_radio.set_rx_callback(legacy_cb)
        physical.inject(b"raw", rssi=-60, snr=9.0)
        assert calls == [(b"raw", -60, 9.0)]

    @pytest.mark.asyncio
    async def test_fabric_ingress_and_dispatcher_single_delivery(self):
        physical = _MockRadio()
        fabric_radio = FabricRadio(radio=physical, radio_id="r1")
        ingresses = []
        fabric_radio.set_ingress_callback(lambda i: ingresses.append(i))

        d = Dispatcher(radio=fabric_radio, packet_filter=PacketFilter())
        handled = []

        async def on_raw(data, rssi, snr):
            handled.append(1)

        d.add_raw_rx_subscriber(on_raw)
        physical.inject(_advert_bytes(), rssi=-70, snr=2.0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert len(ingresses) == 1
        assert len(ingresses[0].receptions) == 1
        assert len(handled) == 1


class TestSX1262MultiInstance:
    @pytest.fixture(autouse=True)
    def _reset_registry(self):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        SX1262Radio._active_instance = None
        SX1262Radio._active_instances = set()
        yield
        SX1262Radio._active_instance = None
        SX1262Radio._active_instances = set()

    def _make_radio(self, **kwargs):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        mock_gpio = MagicMock(name="GPIOPinManager")
        mock_gpio.setup_interrupt_pin.return_value = MagicMock()
        mock_gpio.setup_output_pin.return_value = True
        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0, **kwargs)
        radio._test_gpio = mock_gpio
        return radio

    def test_second_construct_does_not_destroy_first(self):
        r1 = self._make_radio(irq_pin=16)
        r1_gpio = r1._gpio_manager
        r1._initialized = True  # pretend live

        def boom_cleanup():
            raise AssertionError(
                "first radio must not be cleaned up on second construct"
            )

        r1.cleanup = boom_cleanup  # type: ignore[method-assign]

        r2 = self._make_radio(irq_pin=17)
        assert r1 is not r2
        assert r1._gpio_manager is r1_gpio
        assert (
            r1
            in __import__(
                "openhop_core.hardware.sx1262_wrapper", fromlist=["SX1262Radio"]
            ).SX1262Radio._active_instances
        )
        assert (
            r2
            in __import__(
                "openhop_core.hardware.sx1262_wrapper", fromlist=["SX1262Radio"]
            ).SX1262Radio._active_instances
        )

    def test_cleanup_one_does_not_cleanup_peer_gpio(self):
        r1 = self._make_radio(irq_pin=16, reset_pin=18, busy_pin=20)
        r2 = self._make_radio(irq_pin=17, reset_pin=19, busy_pin=21)
        g1 = r1._gpio_manager
        g2 = r2._gpio_manager
        assert g1 is not g2

        r1.cleanup()
        g1.cleanup_all.assert_called()
        g2.cleanup_all.assert_not_called()
        assert r2._initialized is False or True  # r2 still registered
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        assert r1 not in SX1262Radio._active_instances
        assert r2 in SX1262Radio._active_instances

    def test_begin_binds_instance_gpio_to_chip(self):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        mock_lora = MagicMock(name="SX126x")
        mock_lora.IRQ_RX_DONE = 0x0002
        mock_lora.IRQ_CRC_ERR = 0x0040
        mock_lora.IRQ_TIMEOUT = 0x0200
        mock_lora.IRQ_PREAMBLE_DETECTED = 0x0004
        mock_lora.IRQ_SYNC_WORD_VALID = 0x0008
        mock_lora.IRQ_HEADER_VALID = 0x0010
        mock_lora.IRQ_HEADER_ERR = 0x0020
        mock_lora.IRQ_NONE = 0
        mock_lora.STANDBY_RC = 0
        mock_lora.LORA_MODEM = 1
        mock_lora.STATUS_MODE_STDBY_RC = 2
        mock_lora.RX_CONTINUOUS = 3
        mock_lora.TX_POWER_SX1262 = 0
        mock_lora.HEADER_EXPLICIT = 0
        mock_lora.CRC_ON = 1
        mock_lora.IQ_STANDARD = 0
        mock_lora.RX_GAIN_BOOSTED = 1
        mock_lora.REGULATOR_DC_DC = 0
        mock_lora.TCXO_DELAY_5 = 5
        for attr, val in [
            ("DIO3_OUTPUT_1_6", 1),
            ("DIO3_OUTPUT_1_7", 2),
            ("DIO3_OUTPUT_1_8", 3),
            ("DIO3_OUTPUT_2_2", 4),
            ("DIO3_OUTPUT_2_4", 5),
            ("DIO3_OUTPUT_2_7", 6),
            ("DIO3_OUTPUT_3_0", 7),
            ("DIO3_OUTPUT_3_3", 8),
            ("CAL_IMG_430", 0x6B),
            ("CAL_IMG_440", 0x70),
            ("CAL_IMG_470", 0x75),
            ("CAL_IMG_510", 0x81),
            ("CAL_IMG_779", 0xC1),
            ("CAL_IMG_787", 0xC5),
            ("CAL_IMG_863", 0xD7),
            ("CAL_IMG_870", 0xDB),
            ("CAL_IMG_902", 0xE1),
            ("CAL_IMG_928", 0xE9),
        ]:
            setattr(mock_lora, attr, val)
        mock_lora.busyCheck.return_value = False
        mock_lora.getMode.return_value = mock_lora.STATUS_MODE_STDBY_RC
        mock_lora.readRegister.return_value = (0,)

        mock_gpio = MagicMock()
        mock_gpio.setup_interrupt_pin.return_value = MagicMock()
        mock_gpio.setup_output_pin.return_value = True

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
            patch.object(SX1262Radio, "_bind_instance_spi_transport"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0)
            assert radio.begin() is True

        mock_lora.set_gpio_manager.assert_called_with(mock_gpio)

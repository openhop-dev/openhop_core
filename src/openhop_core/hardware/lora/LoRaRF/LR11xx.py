import math

from .SX126x import SX126x


class LR11xx(SX126x):
    """Class for LR1110/20/21 LoRa chipsets from Semtech

    The LR11xx LoRa modem takes the same SF, bandwidth (62.5 to 500 kHz below
    1 GHz), coding rate, header, CRC, IQ and CAD exit encodings as the SX126x,
    behind 16-bit opcodes and a two-step SPI read. This class reuses the SX126x
    pin, SPI and busy handling and overrides the commands, following the LR1121
    user manual (UM).
    """

    # SetTcxoMode delay in 30.52 us steps
    TCXO_DELAY_5 = 0x0000A4  # 5 ms

    # SetPacketType
    LORA_MODEM = 0x02

    # SetTxParams
    PA_RAMP_48U = 0x02  # ramp time: 48 us

    # SetDioIrqParams and GetStatus
    IRQ_TX_DONE = 0x0004
    IRQ_RX_DONE = 0x0008
    IRQ_PREAMBLE_DETECTED = 0x0010
    IRQ_SYNC_WORD_VALID = 0x0020  # one flag for sync word and header valid
    IRQ_HEADER_VALID = 0x0020
    IRQ_HEADER_ERR = 0x0040
    IRQ_CRC_ERR = 0x0080
    IRQ_CAD_DONE = 0x0100
    IRQ_CAD_DETECTED = 0x0200
    IRQ_TIMEOUT = 0x0400

    # SetCadParams takes the number of symbols itself
    CAD_ON_1_SYMB = 0x01
    CAD_ON_2_SYMB = 0x02
    CAD_ON_4_SYMB = 0x04
    CAD_ON_8_SYMB = 0x08
    CAD_ON_16_SYMB = 0x10

    ### COMMON OPERATIONAL METHODS ###

    def sleep(self, option=SX126x.SLEEP_COLD_START):
        # retention without an RTC wake-up is RFU on LR11xx (UM table 2-8)
        super().sleep(option)

    def request(self, timeout: int = SX126x.RX_SINGLE) -> bool:
        # An explicit header longer than PayloadLen is rejected with a HeaderErr
        # (UM 8.3.2), so lift the last TX length back to 255 before listening.
        # From standby, as MeshCore does for LR11xx after a header error.
        self.setStandby(self.STANDBY_RC)
        self.setPacketParamsLoRa(
            self._preambleLength, self._headerType, 0xFF, self._crcType, self._invertIq
        )
        return super().request(timeout)

    ### HARDWARE CONFIGURATION METHODS ###

    def setDio2RfSwitch(self, enable: bool = True):
        # DIO2 has no RF switch role on LR11xx, see setDioAsRfSwitch
        pass

    def setFrequency(self, frequency: int):
        # image calibration around the channel in 4 MHz steps (UM 2.1.3.1)
        mhz = frequency / 1000000
        self.calibrateImage(int((mhz - 1) // 4), math.ceil((mhz + 1) / 4))
        self.setRfFrequency(frequency)

    def setTxPower(self, txPower: int, version=None):
        # high power PA fed from VBAT, which it needs above +14 dBm (UM 9.5)
        txPower = max(-9, min(22, txPower))
        self.setPaConfig(0x01, 0x01, 0x04, 0x07)
        self.setTxParams(txPower, self.PA_RAMP_48U)

    def setRxGain(self, rxGain):
        # SetRxBoosted: 1 enables the boosted gain
        self._rxGain = rxGain
        self._writeBytes(0x0227, (rxGain,), 1)

    ### LR11XX API: OPERATIONAL MODES COMMANDS ###

    def setSleep(self, sleepConfig: int):
        # sleep time 0: no wake-up on the RTC
        self._writeBytes(0x011B, (sleepConfig, 0, 0, 0, 0), 5)

    def setStandby(self, stbyConfig: int):
        self._writeBytes(0x011C, (stbyConfig,), 1)

    def setTx(self, timeout: int):
        # timeout in 30.52 us steps
        self._writeBytes(0x020A, tuple(timeout.to_bytes(3, "big")), 3)

    def setRx(self, timeout: int):
        self._writeBytes(0x0209, tuple(timeout.to_bytes(3, "big")), 3)

    def setCad(self):
        self._writeBytes(0x0218, (), 0)

    def setRegulatorMode(self, modeParam: int):
        self._writeBytes(0x0110, (modeParam,), 1)

    def calibrate(self, calibParam: int):
        # bits 7:6 are RFU, 0x3F calibrates every block
        self._writeBytes(0x010F, (calibParam & 0x3F,), 1)

    def calibrateImage(self, freq1: int, freq2: int):
        self._writeBytes(0x0111, (freq1, freq2), 2)

    def setPaConfig(self, paSel: int, regPaSupply: int, paDutyCycle: int, paHpSel: int):
        self._writeBytes(0x0215, (paSel, regPaSupply, paDutyCycle, paHpSel), 4)

    ### LR11XX API: REGISTER AND BUFFER ACCESS COMMANDS ###

    def writeBuffer(self, offset: int, data: tuple, nData: int):
        # the chip keeps its own TX buffer pointer (UM 8.8)
        self._writeBytes(0x0109, data, nData)

    def readBuffer(self, offset: int, nData: int) -> tuple:
        return self._readBytes(0x010A, nData, (offset, nData), 2)

    def setBufferBaseAddress(self, txBaseAddress: int, rxBaseAddress: int):
        # no base addresses, the chip handles both buffer pointers (UM 8.8)
        pass

    ### LR11XX API: DIO AND IRQ CONTROL ###

    def setDioIrqParams(self, irqMask: int, dio1Mask: int, dio2Mask: int, dio3Mask: int):
        # no global mask: IRQ pins DIO9 and DIO11 take their own masks
        buf = tuple(dio1Mask.to_bytes(4, "big") + dio2Mask.to_bytes(4, "big"))
        self._writeBytes(0x0113, buf, 8)

    def getIrqStatus(self) -> int:
        # GetStatus answers Stat1, Stat2 and IrqStatus(31:0) in one transaction,
        # the radio interrupts all sit in the low 16 bits
        buf = super()._readBytes(0x01, 5)
        return (buf[3] << 8) | buf[4]

    def clearIrqStatus(self, clearIrqParam: int):
        self._writeBytes(0x0114, tuple(clearIrqParam.to_bytes(4, "big")), 4)

    def setDio3AsTcxoCtrl(self, tcxoVoltage: int, delay: int):
        # SetTcxoMode supplies the TCXO on VTCXO, same voltage codes as SX126x DIO3
        self._writeBytes(0x0117, (tcxoVoltage,) + tuple(delay.to_bytes(3, "big")), 4)

    def setDioAsRfSwitch(self, enable, standby, rx, tx, txHp, txHf, gnss, wifi):
        # bit n of each byte drives RFSWn: DIO5, DIO6, DIO7, DIO8, DIO10 (UM 4.2.1);
        # gnss and wifi are RFU on LR1121
        self._writeBytes(0x0112, (enable, standby, rx, tx, txHp, txHf, gnss, wifi), 8)

    ### LR11XX API: RF, MODULATION, AND PACKET COMMANDS ###

    def setRfFrequency(self, rfFreq: int):
        # frequency in Hz
        self._writeBytes(0x020B, tuple(rfFreq.to_bytes(4, "big")), 4)

    def setPacketType(self, packetType: int):
        self._writeBytes(0x020E, (packetType,), 1)

    def setTxParams(self, power: int, rampTime: int):
        self._writeBytes(0x0211, (power & 0xFF, rampTime), 2)

    def setModulationParamsLoRa(self, sf: int, bw: int, cr: int, ldro: int):
        self._writeBytes(0x020F, (sf, bw, cr, ldro), 4)

    def setPacketParamsLoRa(
        self, preambleLength: int, headerType: int, payloadLength: int, crcType: int, invertIq: int
    ):
        # kept for request()
        self._preambleLength = preambleLength
        self._headerType = headerType
        self._crcType = crcType
        self._invertIq = invertIq
        buf = tuple(preambleLength.to_bytes(2, "big"))
        self._writeBytes(0x0210, buf + (headerType, payloadLength, crcType, invertIq), 6)

    def setCadParams(
        self, cadSymbolNum: int, cadDetPeak: int, cadDetMin: int, cadExitMode: int, cadTimeout: int
    ):
        buf = (cadSymbolNum, cadDetPeak, cadDetMin, cadExitMode)
        self._writeBytes(0x020D, buf + tuple(cadTimeout.to_bytes(3, "big")), 7)

    ### LR11XX API: STATUS COMMANDS ###

    def getRxBufferStatus(self) -> tuple:
        return self._readBytes(0x0203, 2)

    def getPacketStatus(self) -> tuple:
        return self._readBytes(0x0204, 3)

    def getRssiInst(self) -> int:
        return self._readBytes(0x0205, 1)[0]

    def getDeviceErrors(self) -> int:
        buf = self._readBytes(0x010D, 2)
        return (buf[0] << 8) | buf[1]

    ### LR11XX API: WORKAROUND FUNCTIONS ###

    def _fixResistanceAntenna(self):
        # SX126x TX clamp register, no LR11xx equivalent
        pass

    ### LR11XX API: UTILITIES ###

    def _writeBytes(self, opCode: int, data: tuple, nBytes: int):
        # 16-bit opcode: the high byte goes out as the SX126x opcode
        super()._writeBytes(opCode >> 8, (opCode & 0xFF,) + tuple(data[:nBytes]), nBytes + 1)

    def _readBytes(self, opCode: int, nBytes: int, address: tuple = (), nAddress: int = 0) -> tuple:
        # two transactions: the command, then NOPs clocking out Stat1 and the
        # response (UM 3.2), and the SX126x read already drops that first byte
        self._writeBytes(opCode, address, nAddress)
        return super()._readBytes(0x00, nBytes)

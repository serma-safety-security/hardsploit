from time import sleep

from hardsploit.core import HardsploitError
from hardsploit.modules import HardsploitSPI


def bv(x):
    return 1 << x


class NRF24L01:
    # Instruction Mnemonics
    R_REGISTER = 0x00
    W_REGISTER = 0x20
    REGISTER_MASK = 0x1F
    ACTIVATE = 0x50
    R_RX_PL_WID = 0x60
    R_RX_PAYLOAD = 0x61
    W_TX_PAYLOAD = 0xA0
    W_ACK_PAYLOAD = 0xA8
    FLUSH_TX = 0xE1
    FLUSH_RX = 0xE2
    REUSE_TX_PL = 0xE3
    NOP = 0xFF

    # Register map
    _00_CONFIG = 0x00
    _01_EN_AA = 0x01
    _02_EN_RXADDR = 0x02
    _03_SETUP_AW = 0x03
    _04_SETUP_RETR = 0x04
    _05_RF_CH = 0x05
    _06_RF_SETUP = 0x06
    _07_STATUS = 0x07
    _08_OBSERVE_TX = 0x08
    _09_CD = 0x09
    _0A_RX_ADDR_P0 = 0x0A
    _0B_RX_ADDR_P1 = 0x0B
    _0C_RX_ADDR_P2 = 0x0C
    _0D_RX_ADDR_P3 = 0x0D
    _0E_RX_ADDR_P4 = 0x0E
    _0F_RX_ADDR_P5 = 0x0F
    _10_TX_ADDR = 0x10
    _11_RX_PW_P0 = 0x11
    _12_RX_PW_P1 = 0x12
    _13_RX_PW_P2 = 0x13
    _14_RX_PW_P3 = 0x14
    _15_RX_PW_P4 = 0x15
    _16_RX_PW_P5 = 0x16
    _17_FIFO_STATUS = 0x17
    _1C_DYNPD = 0x1C
    _1D_FEATURE = 0x1D

    # Bit mnemonics
    _00_MASK_RX_DR = 6
    _00_MASK_TX_DS = 5
    _00_MASK_MAX_RT = 4
    _00_EN_CRC = 3
    _00_CRCO = 2
    _00_PWR_UP = 1
    _00_PRIM_RX = 0
    _07_RX_DR = 6
    _07_TX_DS = 5
    _07_MAX_RT = 4

    # Bitrates
    _BR_1M = 0
    _BR_2M = 1
    _BR_250K = 2
    _BR_RSVD = 3

    TXRX_OFF = 0
    TX_EN = 1
    RX_EN = 2

    def __init__(self, hardsploit_api):
        self._spi = HardsploitSPI(8, 0, hardsploit_api)  # 150/(2*8) = 9.3MHz
        self._rf_setup = 0x0F
        self._tout = 0

    def send_recv_spi(self, packet):
        try:
            return self._spi.spi_interact(packet)
        except HardsploitError.HardsploitNotFound:
            print("[!] Hardsploit Not found !")
        except HardsploitError.USBError:
            print("[!] USB ERROR")

    def init_drone(self, channel, address):
        config = bv(NRF24L01._00_EN_CRC) | bv(NRF24L01._00_CRCO) | bv(NRF24L01._00_PRIM_RX)
        self.write_reg(NRF24L01._00_CONFIG, config)
        self.write_reg(NRF24L01._01_EN_AA, 0x0f)        # Auto Acknoledgement
        self.activate(0x73)                             # Allow to write feature reg
        self.write_reg(NRF24L01._1D_FEATURE, 0x06)       # enableDynamicPayloads
        self.write_reg(NRF24L01._1C_DYNPD, 0x3f)         # enableDynamicPayloads
        self.write_reg(NRF24L01._02_EN_RXADDR, 0x01)    # Enable data pipe 0
        self.write_reg(NRF24L01._03_SETUP_AW, 0x03)     # 5-byte RX/TX address
        # self.write_reg(NRF24L01._04_SETUP_RETR, 0xFF)   # 4ms retransmit t/o, 15 tries
        self.write_reg(NRF24L01._05_RF_CH, channel)     # Channel  - bind
        self.set_bitrate(NRF24L01._BR_250K)
        self.set_power(3)                               # Max power
        self.write_reg(NRF24L01._07_STATUS, 0x70)       # Clear data ready, data
        self.write_reg(NRF24L01._11_RX_PW_P0, 16)
        self.write_reg(NRF24L01._17_FIFO_STATUS, 0x00)
        self.write_reg_multi(NRF24L01._0A_RX_ADDR_P0, address)
        self.write_reg_multi(NRF24L01._10_TX_ADDR, address)

        config |= bv(NRF24L01._00_PWR_UP)
        self.write_reg(NRF24L01._00_CONFIG, config)

        self.set_tx_rx_mode(NRF24L01.TXRX_OFF)
        self.set_tx_rx_mode(NRF24L01.RX_EN)

    def write_reg(self, reg, data):
        result = self.send_recv_spi([(NRF24L01.W_REGISTER | (NRF24L01.REGISTER_MASK & reg)), data])
        return result[1]

    def write_reg_multi(self, reg, payload):
        tmp_payload = [NRF24L01.W_REGISTER | (NRF24L01.REGISTER_MASK & reg)]
        tmp_payload += payload
        result = self.send_recv_spi(tmp_payload)
        return result[0]

    def write_payload(self, payload):
        tmp_wpayload = [NRF24L01.W_TX_PAYLOAD]
        tmp_wpayload += payload
        result = self.send_recv_spi(tmp_wpayload)
        return result[0]

    def read_reg(self, reg):
        result = self.send_recv_spi([NRF24L01.R_REGISTER | (NRF24L01.REGISTER_MASK & reg), 0xFF])
        return result[1]

    def read_payload_size(self):
        result = self.send_recv_spi([NRF24L01.R_RX_PL_WID, 0xFF])
        return result[1]

    def read_reg_multi(self, reg, length):
        tab = [NRF24L01.R_REGISTER | (NRF24L01.REGISTER_MASK & reg)]
        tab.push += [0xFF] * length
        return self.send_recv_spi(tab)[1:]  # remove the first byte

    def read_payload(self, length):
        tab = [NRF24L01.R_RX_PAYLOAD]
        tab += [0xFF] * length
        return self.send_recv_spi(tab)[1:]  # remove the first byte

    def read_available_data(self):
        payload_size = self.read_payload_size()
        return self.read_payload(payload_size)

    def strobe(self, state):
        result = self.send_recv_spi([state])
        return result[0]

    def flush_tx(self):
        return self.strobe(NRF24L01.FLUSH_TX)

    def flush_rx(self):
        return self.strobe(NRF24L01.FLUSH_RX)

    def activate(self, code):
        result = self.send_recv_spi([NRF24L01.ACTIVATE, code])
        return result[0]

    def data_available(self):
        result = self.send_recv_spi([NRF24L01.R_REGISTER, NRF24L01._07_STATUS])
        if ((result[0] & bv(NRF24L01._07_RX_DR)) >> 6) == 1:
            return True
        else:
            return False

    def change_channel(self, channel):
        self.write_reg(NRF24L01._05_RF_CH, channel)

    def set_bitrate(self, bit_rate):
        # Note that bit rate 250kbps (and bit RF_DR_LOW) is valid only
        # for nRF24L01+. There is no way to programmatically tell it from
        # older version, nRF24L01, but the older is practically phased out
        # by Nordic, so we assume that we deal with modern version.

        # Bit 0 goes to RF_DR_HIGH, bit 1 - to RF_DR_LOW
        self._rf_setup = (self._rf_setup & 0xD7) | ((bit_rate & 0x02) << 4) | ((bit_rate & 0x01) << 3)
        return self.write_reg(NRF24L01._06_RF_SETUP, self._rf_setup)

    # Power setting is 0..3 for nRF24L01
    def set_power(self, nrf_power):
        if (nrf_power < 0) or (nrf_power > 3):
            raise ValueError("NRF setPower, wrong must be between 0 and 3")
        self._rf_setup = (self._rf_setup & 0xF9) | ((nrf_power & 0x03) << 1)
        return self.write_reg(NRF24L01._06_RF_SETUP, self._rf_setup)

    def ce_lo(self):
        self._spi.pulse = 0

    def ce_hi(self):
        self._spi.pulse = 1

    def set_tx_rx_mode(self, mode):
        if mode == NRF24L01.TX_EN:
            self.ce_lo()
            # sleep(0.5)
            self.write_reg(NRF24L01._07_STATUS, (1 << NRF24L01._07_RX_DR) | (1 << NRF24L01._07_TX_DS) | (1 << NRF24L01._07_MAX_RT))   # reset the flag(s)
            self.write_reg(NRF24L01._00_CONFIG, (1 << NRF24L01._00_EN_CRC) | (1 << NRF24L01._00_CRCO) | (1 << NRF24L01._00_PWR_UP))  # switch to TX mode
            # sleep(0.5)
            self.ce_hi()
        elif mode == NRF24L01.RX_EN:
            self.ce_lo()
            # sleep(0.5)
            self.write_reg(NRF24L01._07_STATUS, 0x70)        # reset the flag(s)
            self.write_reg(NRF24L01._00_CONFIG, 0x0F)        # switch to RX mode
            self.write_reg(NRF24L01._07_STATUS, (1 << NRF24L01._07_RX_DR) | (1 << NRF24L01._07_TX_DS) | (1 << NRF24L01._07_MAX_RT))  # reset the flag(s)
            self.write_reg(NRF24L01._00_CONFIG, (1 << NRF24L01._00_EN_CRC) | (1 << NRF24L01._00_CRCO) | (1 << NRF24L01._00_PWR_UP) | (1 << NRF24L01._00_PRIM_RX))  # switch to RX mode
            # sleep(0.5)
            self.ce_hi()
        else:
            self.write_reg(NRF24L01._00_CONFIG, (1 << NRF24L01._00_EN_CRC))  # PowerDown
            self.ce_lo()

    def reset(self):
        self.set_tx_rx_mode(NRF24L01.TXRX_OFF)
        self.flush_tx()
        self.flush_rx()
        return True

    def read(self):
        tabdataread = []
        if self.data_available():
            self.write_reg(0x07, bv(NRF24L01._07_RX_DR))
            tabdataread += self.read_payload(16)
            return tabdataread
        else:
            return tabdataread

    def send(self, data_send):
        self.set_tx_rx_mode(NRF24L01.TXRX_OFF)
        self.flush_tx()
        self.write_payload(data_send)
        self.set_tx_rx_mode(NRF24L01.TX_EN)
        sleep(0.4)
        self.set_tx_rx_mode(NRF24L01.TXRX_OFF)
        self.flush_tx()
        self.flush_rx()
        self.set_tx_rx_mode(NRF24L01.RX_EN)

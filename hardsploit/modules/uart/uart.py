import time
from hardsploit.core import HardsploitUtils, HardsploitError


class HardsploitUART:

    def __init__(self, baud_rate, word_width, use_parity_bit, parity_type, nb_stop_bits, idle_line_level, hardsploit_api):
        self._baud_rate = baud_rate
        self.__word_width = word_width
        self.__use_parity_bit = use_parity_bit
        self.__parity_type = parity_type
        self.__nb_stop_bits = nb_stop_bits
        self.__idle_line_level = idle_line_level
        self.__api = hardsploit_api
        self.__payload_TX = []
        self.set_settings()

    @property
    def baud_rate(self):
        return int(150000000 / self._baud_rate)

    @baud_rate.setter
    def baud_rate(self, baud_rate):
        if (baud_rate >= 2400) and (baud_rate <= 1036800):
            self._baud_rate = 150000000 / baud_rate
        else:
            raise HardsploitError.UARTWrongSettings

    @property
    def word_width(self):
        return self.__word_width

    @word_width.setter
    def word_width(self, word_width):
        if (word_width >= 5) and (word_width <= 8):
            self.__word_width = word_width
        else:
            raise HardsploitError.UARTWrongSettings

    @property
    def use_parity_bit(self):
        return self.__use_parity_bit

    @use_parity_bit.setter
    def use_parity_bit(self, use_parity_bit):
        if (use_parity_bit >= 0) and (use_parity_bit <= 1):
            self.__use_parity_bit = use_parity_bit
        else:
            raise HardsploitError.UARTWrongSettings

    @property
    def parity_type(self):
        return self.__parity_type

    @parity_type.setter
    def parity_type(self, parity_type):
        if (parity_type >= 0) and (parity_type <= 1):
            self.__parity_type = parity_type
        else:
            raise HardsploitError.UARTWrongSettings

    @property
    def nb_stop_bits(self):
        return self.__nb_stop_bits

    @nb_stop_bits.setter
    def nb_stop_bits(self, nb_stop_bits):
        if (nb_stop_bits >= 1) and (nb_stop_bits <= 2):
            self.__nb_stop_bits = nb_stop_bits
        else:
            raise HardsploitError.UARTWrongSettings

    @property
    def idle_line_level(self):
        return self.__idle_line_level

    @idle_line_level.setter
    def idle_line_level(self, idle_line_level):
        if (idle_line_level >= 0) and (idle_line_level <= 1):
            self.__idle_line_level = idle_line_level
        else:
            raise HardsploitError.UARTWrongSettings

    #  write
    # * +payload+:: Byte array want to send
    # * Return nothing
    def write(self, payload):
        if len(self.__payload_TX) + len(payload) > 4000:
            raise HardsploitError.UARTWrongTxPayloadSize
        self.__payload_TX += payload  # Add data

    # sendAndReceived  ( send and receive)
    # First write data if needed and refresh (data are sent and received data if needed) and you obtain available data
    # * Return nothing
    def send_and_received(self):
        packet = self.__api.prepare_packet()
        packet.append(0x20)  # Send command
        packet += self.__payload_TX
        try:
            tmp_data = self.__api.send_and_receive_data(packet, 1000)
        except:
            raise HardsploitError.USBError
        self.__payload_TX.clear()
        # remove header (4 bytes   2 for size 2 for type of command + 1 dummy byte)
        return tmp_data[5:]

    # enableMeasureBaudRate
    #
    # *
    def enable_measure_baud_rate(self):
        packet = self.__api.prepare_packet()
        packet.append(0x41)  # command
        try:
            self.__api.send_and_receive_data(packet, 1000)
        except:
            raise HardsploitError.USBError

    # disableMeasureBaudRate
    #
    # *
    def disable_measure_baud_rate(self):
        packet = self.__api.prepare_packet()
        packet.append(0x40)  # command
        try:
            self.__api.send_and_receive_data(packet, 1000)
        except:
            raise HardsploitError.USBError

    # measureBaudRate
    #
    # * Return 32 bits period
    def measure_baud_rate(self):
        packet = self.__api.prepare_packet()
        packet.append(0x30)  # command

        try:
            tmp_data = self.__api.send_and_receive_data(packet, 1000)
        except:
            raise HardsploitError.USBError

        # remove header (4 bytes   2 for size 2 for type of command)
        tmp_data = tmp_data[4:]
        period = tmp_data[0] + (tmp_data[1] << 8) + (tmp_data[2] << 16) + (tmp_data[3] << 24)
        period = period * 33.33 * (10 ** -9)  # s
        if period > 0:
            return int((1 / period))
        else:
            return 0

    #  settings
    # * Return nothing
    def set_settings(self):
        packet = self.__api.prepare_packet()
        packet.append(0x00)  # Settings command
        temp_result = bin((self.parity_type & 0b1) << 7) or bin((self.use_parity_bit & 0b1) << 6) or bin(
                    (self.nb_stop_bits & 0b11) << 4) or bin(self.word_width & 0b1111)
        packet.append((int(temp_result, 2)))
        packet.append(self.idle_line_level & 1)
        packet.append(HardsploitUtils.low_byte(word=self.baud_rate))
        packet.append(HardsploitUtils.high_byte(word=self.baud_rate))

        try:
            self.__api.send_packet(packet)
            time.sleep(1)
        # tmp= HardsploitAPI.instance.receiveDATA(1000)
        # remove header (4 bytes   2 for size 2 for type of command)
        # return tmp.bytes.drop(4)
        except:
            raise HardsploitError.USBError

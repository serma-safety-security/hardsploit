from hardsploit.core import HardsploitError, HardsploitUtils, HardsploitConstant


class HardsploitSPISniffer:

    def __init__(self, mode, sniff, hardsploit_api):
        # to be sure the singleton was initialized
        self.__mode = mode
        self.__sniff = sniff
        self.__api = hardsploit_api
        self.spi_set_settings()

    @property
    def mode(self):
        return self.__mode

    @mode.setter
    def mode(self, mode):
        if mode < 0 or mode > 3:
            raise HardsploitError.SPIWrongMode
        else:
            self.__mode = mode

    @property
    def sniff(self):
        return self.__sniff

    @sniff.setter
    def sniff(self, sniff):
        if sniff == HardsploitConstant.SPISniffer.MISO:
            self.__sniff = sniff
        elif sniff == HardsploitConstant.SPISniffer.MOSI:
            self.__sniff = sniff
        elif sniff == HardsploitConstant.SPISniffer.MISO_MOSI:
            self.__sniff = sniff
        else:
            raise HardsploitError.SPIWrongMode

    def spi_set_settings(self):
        packet = self.__api.prepare_packet()
        packet.append(0x10)  # Command change mode
        packet.append(self.mode + (self.sniff << 6))  # Add mode
        try:
            self.__api.send_packet(packet)
        except:
            raise HardsploitError.USBError

    #  spi_receive_available_data
    # * Return data received
    def spi_receive_available_data(self):
        packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND), 0x50, 0x20]

        # remove header (4 bytes   2 for size 2 for type of command)
        result = self.__api.send_and_receive_data(packet, 200)[4:]

        # if half a simple array, if full-duplex  first item -> an array of MISO  and second array -> an array of MOSI
        if self.sniff in [HardsploitConstant.SPISniffer.MOSI, HardsploitConstant.SPISniffer.MISO]:
            return result
        else:
            myresult = [HardsploitUtils.odds_and_evens(result, True),
                        HardsploitUtils.odds_and_evens(result, False)]
            return myresult

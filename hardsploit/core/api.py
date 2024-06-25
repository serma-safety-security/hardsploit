from colorama import Fore, Style
import itertools

from hardsploit.core import HardsploitFirmware, HardsploitUtils, HardsploitConstant, HardsploitError
from hardsploit.firmwares import VersionFPGA, VersionUC


class HardsploitAPI(HardsploitFirmware):
    id = 0
    crossWiringValue = []
    callbackProgress = None
    callbackData = None

    def __init__(self):
        super().__init__()

        if HardsploitAPI.id < 0:
            raise HardsploitError.HardsploitNotFound

        self.id = HardsploitAPI.id
        self.crossWiringValue = HardsploitAPI.crossWiringValue
        # Default wiring
        for i in range(64):
            self.crossWiringValue.append(i)
        self.connect()
        print(Fore.GREEN + "Hardsploit is connected" + Style.RESET_ALL)

    # Set custom value to wiring led
    # * +value+:: 64 bits (8x8 Bytes) values to represent led (PortH PortG PortF PortE PortD PortC PortB PortA)
    def set_wiring_leds(self, value):
        #  parameters = HardsploitAPI.checkParameters(["value"],args)
        #  val = parameters[:value]
        packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND), 0x23,
                  HardsploitUtils.reverse_bit((value & 0x00000000000000FF) >> 0),
                  HardsploitUtils.reverse_bit((value & 0x000000000000FF00) >> 8),
                  HardsploitUtils.reverse_bit((value & 0x0000000000FF0000) >> 16),
                  HardsploitUtils.reverse_bit((value & 0x00000000FF000000) >> 24),
                  HardsploitUtils.reverse_bit((value & 0x000000FF00000000) >> 32),
                  HardsploitUtils.reverse_bit((value & 0x0000FF0000000000) >> 40),
                  HardsploitUtils.reverse_bit((value & 0x00FF000000000000) >> 48),
                  HardsploitUtils.reverse_bit((value & 0xFF00000000000000) >> 56)]
        return self.send_packet(packet)

    # Obtain the version number of the board
    def get_version_number(self):
        packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.GET_VERSION_NUMBER),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.GET_VERSION_NUMBER)]
        # Remove header
        version_number = self.send_and_receive_data(packet, 1000)[4:]
        if len(version_number) < 20:  # if size more thant 20 char error when reading version number
            return bytes(version_number).decode()
        return "BAD VERSION NUMBER"

    def get_all_versions(self):
        print(Fore.BLUE + Style.BRIGHT + f"API             : {HardsploitConstant.VERSION.API}")
        print(Fore.BLUE + Style.BRIGHT + f"Board           : {self.get_version_number()}")
        print(Fore.BLUE + Style.BRIGHT + f"FPGA            : {VersionFPGA.VERSION_FPGA.FPGA}")
        print(Fore.BLUE + Style.BRIGHT + f"Microcontroller : {VersionUC.VERSION_UC.UC}")
        print(Style.RESET_ALL)

    # Set cross wiring
    # * +value+:: 64*8 bits to represent wiring
    def set_cross_wiring(self, value):
        if len(value) != 64:
            raise HardsploitError.ApiCrossWiring

        packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND), 0x75]

        packet += value
        self.crossWiringValue = value
        return self.send_packet(packet)

    @staticmethod
    def all_posibility(number_of_connected_pin_from_a0, number_of_signals_for_bus):
        if number_of_connected_pin_from_a0 < number_of_signals_for_bus:
            raise HardsploitError.ApiScannerWrongPinNumber

        a = []
        for i in range(number_of_connected_pin_from_a0 - 1):
            a.append(i)

        return list(itertools.permutations(a))

    @staticmethod
    def prepare_packet():
        packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND), 0x50]
        return packet

    # Power on the LED for each signal specified
    # Params:
    # +signal+:: Name of signal you want visual help (set the LED)
    def signal_helping_wiring(self, signal):
        try:
            self.set_wiring_leds(
                value=2 ** HardsploitAPI.crossWiringValue.index(HardsploitConstant.get_signal_id(signal=signal)))
        except:
            print('UNKNOWN SIGNAL')

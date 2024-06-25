""""
SPI_CLK --> Pin A0
CS      --> Pin A1
MOSI    --> Pin A2
MISO    --> Pin A3
PULSE   --> Pin A4
"""
import pathlib
import inspect
from colorama import Fore, Style
import sys
import string

from hardsploit.core import HardsploitAPI, HardsploitConstant, HardsploitError, HardsploitUtils
from hardsploit.modules import HardsploitSPI, HardsploitSPISniffer

hardsploit_package = pathlib.Path(pathlib.Path(inspect.getfile(lambda: None)).parents[1])
sys.path.append(hardsploit_package.resolve().as_posix())


def callback_info(receive_data):
    print(receive_data)


def callback_data(receive_data):
    if receive_data:
        print("received {}".format(len(receive_data)))
        print(receive_data)


def callback_speed_of_transfert(receive_data):
    print("Speed : {}".format(receive_data))


def callback_progress(percent, start_time, end_time):
    print(f"Upload of SPI firmware in progress : {percent}")



def get_printable(byte_array):
    result = ""
    for byte in byte_array:
        if byte in bytes(string.printable, 'ascii'):
            result += chr(byte)
    return result


def spi_custom_command():
    # Speed Range 1-255  SPI clock =  150Mhz / (2*speed) tested from 3 to 255 (25Mhz to about 0.3Khz)
    testpack = []
    for i in range(11):
        testpack.append(i)
    result = spiLink.spi_interact(testpack)
    print(bytes(result))


def spi_sniffer():
    i = '.'

    hardsploit.load_firmware("SPI_SNIFFER")
    spi_sniffer = HardsploitSPISniffer(mode=0, sniff=HardsploitConstant.SPISniffer.MISO_MOSI, hardsploit_api=hardsploit)
    while True:
        i = ".." if i == '.' else "."  # just to have a toggle in console to keep alive the console
        try:
            result = spi_sniffer.spi_receive_available_data()

            # if half a simple array, if fullduplex  first item -> an array of MISO  and second array -> an array of MOSI
            if spi_sniffer.sniff == HardsploitConstant.SPISniffer.MISO:
                print("MISO : {}".format(result))
                print("PRINTABLE MISO : {}".format(get_printable(result)))
            elif spi_sniffer.sniff == HardsploitConstant.SPISniffer.MOSI:
                print("MOSI : {}".format(result))
                print("PRINTABLE MOSI : {}".format(get_printable(result)))
            else:
                print("MOSI : {}".format(result[0]))
                print("MISO : {}".format(result[1]))
                print("PRINTABLE MOSI : {}".format(get_printable(result[0])))
                print("PRINTABLE MISO : {}".format(get_printable(result[1])))

        except HardsploitError.HardsploitNotFound:
            raise HardsploitError.HardsploitNotFound
        except HardsploitError.USBError:
            print(i)

            # Ignore time out because we read in continous


def menu():
    while True:
        char = input(Fore.RED + Style.BRIGHT + "Command: " + Style.RESET_ALL)
        if char == "exit":
            print("Thanks for using Hardsploit!")
            sys.exit()
        elif char == "z":
            crossvalue = []
            # Default wiring
            for i in range(64):
                crossvalue.append(i)

            # swap 2 first signal
            crossvalue[0] = 1
            crossvalue[1] = 0
            crossvalue[2] = 2
            crossvalue[3] = 3

            crossvalue[60] = 60
            crossvalue[61] = 61
            crossvalue[62] = 62
            crossvalue[63] = 63

            hardsploit.set_cross_wiring(crossvalue)

            print("cross SWAP")

        elif char == "e":
            crossvalue = []
            # Default wiring
            for i in range(64):
                crossvalue.append(i)

            # swap 2 first signal
            hardsploit.set_cross_wiring(crossvalue)
            print("cross Normal")

        elif char == "w":
            hardsploit.set_status_led(HardsploitConstant.UsbCommand.GREEN_LED, True)
            spiLink.pulse = 1

        elif char == "x":
            hardsploit.set_status_led(HardsploitConstant.UsbCommand.GREEN_LED, False)
            spiLink.pulse = 0

        elif char == "i":
            spi_custom_command()

        elif char == "s":
            spi_sniffer()

        elif char == "p":
            hardsploit.load_firmware("SPI")


def help_menu():
    print(f"{Fore.BLUE}{Style.BRIGHT}Menu:\n"
          "\tz - Cross swap\n"
          "\te - Cross normal\n"
          "\tw - Turn on green light \n"
          "\tx - Turn off green light\n"
          "\ti - SPI custom command\n"
          "\ts - SPI Sniffer\n"
          "\tp - Flash firmware\n"
          "\texit - Stop the execution" + Style.RESET_ALL)


HardsploitAPI.callbackProgress = callback_progress

print(f"Number of hardsploit detected: {HardsploitUtils.get_number_of_board_available()}")

hardsploit = HardsploitAPI()
hardsploit.get_all_versions()

if sys.argv[0] != "nofirmware":
    (hardsploit.load_firmware("UART"))


spiLink = HardsploitSPI(60, 0, hardsploit)

help_menu()
menu()

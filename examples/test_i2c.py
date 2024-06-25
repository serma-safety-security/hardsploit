"""
SDA
SCL
"""

from colorama import Fore, Style
import sys
import string

from hardsploit.core import HardsploitAPI, HardsploitConstant, HardsploitError, HardsploitUtils
from hardsploit.modules import HardsploitI2c


def callback_info(receive_data):
    print(receive_data)


def callback_data(receive_data):
    if receive_data:
        print("received {}".format(len(receive_data)))
        print(receive_data)


def callback_speed_of_transfert(receive_data):
    print("Speed : {}".format(receive_data))


def callback_progress(percent, start_time, end_time):
    print("Upload of FPGA firmware in progress : {}".format(percent))


HardsploitAPI.callbackProgress = callback_progress


def get_printable(byte_array):
    result = ""
    for byte in byte_array:
        if byte in bytes(string.printable, 'ascii'):
            result += chr(byte)
    return result


def i2c_interact():
    try:
        # Create an instance of I2C
        i2c = HardsploitI2c(speed=HardsploitConstant.I2C.KHZ_100, hardsploit_api=hardsploit)

        test_pack = [HardsploitUtils.low_byte(word=2), HardsploitUtils.high_byte(word=2), 0xA0, 0x00, 0x00,
                     HardsploitUtils.low_byte(word=4), HardsploitUtils.high_byte(word=4), 0xA1]

        # interact I2C
        # write with even address
        # read with odd address
        print(test_pack)
        try:
            # result contient les ACK NACK ou les data si dispo cf wiki
            result = i2c.i2c_interact(payload=test_pack)
            print(result)

        except HardsploitError.USBError:
            print("USB ERRROR")

    except HardsploitError.HardsploitNotFound:
        print("Hardsploit not found")


def i2c_scan():
    try:
        # Create an instance of I2C
        i2c = HardsploitI2c(speed=HardsploitConstant.I2C.KHZ_100, hardsploit_api=hardsploit)

        # Change the speed
        i2c.speed = HardsploitConstant.I2C.KHZ_100

        # scan I2C
        print("I2C SCAN: ")
        scan_result = i2c.i2c_scan()

        # check parity of array index to know if a Read or Write address
        # Index 0 is write address because is is even
        # Index 1 is read address because it is  odd

        # Index 160 (0xA0) is write address because is is even
        # Index 161 (0xA1) is read address because is is odd

        # If value is 0 slave address is not available
        # If valude is 1 slave address is available

        for i in range(len(scan_result)):
            if scan_result[i] == 1:
                print("{} {}".format(str(hex(i))[2:], scan_result[i]))

    except HardsploitError.HardsploitNotFound:
        print("Hardsploit not found")
    except HardsploitError.USBError:
        print("USB ERRROR")


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
            crossvalue[0] = 8
            crossvalue[1] = 9

            crossvalue[8] = 0
            crossvalue[9] = 1

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

        elif char == "x":
            hardsploit.set_status_led(HardsploitConstant.UsbCommand.GREEN_LED, False)

        elif char == "i":
            i2c_interact()

        elif char == "s":
            i2c_scan()

        elif char == "p":
            hardsploit.load_firmware("I2C")


def help_menu():
    print(Fore.BLUE + Style.BRIGHT + "Menu:\n"
          "\tz - Cross swap\n"
          "\te - Cross normal\n"
          "\tw - Turn on green light \n"   
          "\tx - Turn off green light\n"
          "\ti - I2C interact\n"
          "\ts - I2C scan\n"
          "\tp - Flash firmware\n"
          "\texit - Stop the execution" + Style.RESET_ALL)


print(f"Number of hardsploit detected: {HardsploitUtils.get_number_of_board_available()}")

hardsploit = HardsploitAPI()
hardsploit.get_all_versions()

if sys.argv[0] != "nofirmware":
    hardsploit.load_firmware("I2C")

help_menu()
menu()

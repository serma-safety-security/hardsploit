import pathlib
import inspect
from colorama import Fore, Style
import sys
import string

from hardsploit.core import HardsploitAPI, HardsploitConstant, HardsploitError, HardsploitUtils
from hardsploit.modules.swd.swd import HardsploitSWD

hardsploit_package = pathlib.Path(pathlib.Path(inspect.getfile(lambda: None)).parents[1])
sys.path.append(hardsploit_package.resolve().as_posix())


def callback_progress(percent, start_time, end_time):
    print(f"Upload of SWD firmware in progress : {percent}")


def callback_info(receive_data):
    print(receive_data)


def callback_data(receive_data):
    if receive_data:
        print("received {}".format(len(receive_data)))
        print(receive_data)


def callback_speed_of_transfert(receive_data):
    print("Speed : {}".format(receive_data))

def menu():
    while True:
        char = input(Fore.RED + Style.BRIGHT + "Command: " + Style.RESET_ALL)
        if char == "exit":
            print("Thanks for using Hardsploit!")
            sys.exit()
        elif char == "d":
            file_path = input("Enter the file path of the file where you want to write the flash data")
            swd.dump_flash(file_path)
        elif char == "h":
            file_path = input("Enter the file path of the file you want to write into the memory.")
            swd.write_flash(file_path)
        elif char == "i":
            print(swd.obtain_codes())
        elif char == "x":
            swd.erase_flash()
        elif char == "p":
            api.load_firmware("swd")

def help_menu():
    print(Fore.BLUE + Style.BRIGHT + "Menu:\n"
          "\td - Dump flash\n"
          "\th - Write flash\n"
          "\ti - Informations \n"   
          "\tx - Erase flash\n"
          "\tp - Flash firmware\n"
          "\texit - Stop the execution" + Style.RESET_ALL)

HardsploitAPI.callbackProgress = callback_progress

print(f"Number of hardsploit detected: {HardsploitUtils.get_number_of_board_available()}")

api = HardsploitAPI()


if sys.argv[0] != "nofirmware":
    api.load_firmware("SWD")

swd = HardsploitSWD("0x8000000", "0x1FFFF7E0", "0xE000ED00", "0x1FFFF7E8", api)

crossvalue = [24, 25, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 0,
              1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
              48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]
api.set_cross_wiring(crossvalue)

help_menu()
menu()

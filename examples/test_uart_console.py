"""
TX --> Pin A0
RX --> Pin A1
"""

from colorama import Fore, Style
import sys
import pathlib
import inspect
import time
import threading

from hardsploit.core import HardsploitAPI, HardsploitError, HardsploitUtils
from hardsploit.modules import HardsploitUART

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
    print(f"Upload of FPGA firmware in progress : {percent}")



HardsploitAPI.callbackProgress = callback_progress


def uart_custom_read():
    print("Start reading...\n")
    while True:
        try:
            tab = uart.send_and_received()
            print(tab)
            print(Fore.CYAN + bytes(tab).decode() + Style.RESET_ALL, end='')
        except HardsploitError.HardsploitNotFound:
            print("Hardsploit not found")
        except HardsploitError.USBError:
            print("USB ERRROR")
        time.sleep(0.1)


def uart_custom_write():
    print("Start writing...\n\n")
    while True:
        stdin_value: str = input()
        if stdin_value == "quit" or stdin_value == "exit" or stdin_value == "stop":
            result = input(f"is '{stdin_value}' an UART command or you want to stop writing? (command|stop): ")
            if result == "stop":
                print("Exit writing...")
                return
            uart.write(bytearray((stdin_value + '\r').encode()))
        else:
            uart.write(bytearray((stdin_value + '\r').encode()))


def menu():
    while True:
        char = input(Fore.RED + Style.BRIGHT + "Command: " + Style.RESET_ALL)
        if char == "exit":
            print("Thanks for using Hardsploit!")
            sys.exit()

        elif char == "e":
            print("Start measuring baudrate")
            uart.enable_measure_baud_rate()

        elif char == "d":
            print("Stop measuring baudrate")
            uart.disable_measure_baud_rate()

        elif char == "m":
            print(f"Actual baudrate {uart._baud_rate}")
            uart._baud_rate = uart.measure_baud_rate()
            uart.set_settings()
            print(f"\nNew baudrate {uart._baud_rate} \n")
        elif char == "w":
            uart_custom_write()
        elif char == "r":
            t1.start()
        elif char == "p":
            hardsploit.load_firmware("UART")
            uart.set_settings()


def help_menu():
    print(Fore.BLUE + Style.BRIGHT + "Menu:\n"
          "\te - Enable measure baudrate\n"
          "\td - Disable measure baudrate\n"
          "\tm - Measure baudrate\n"   
          "\tr - UART custom read\n"
          "\tw - UART custom write\n"
          "\tp - Flash firmware\n"
          "\texit - Stop the execution" + Style.RESET_ALL)


print(f"Number of hardsploit detected: {HardsploitUtils.get_number_of_board_available()}")

hardsploit = HardsploitAPI()
hardsploit.get_all_versions()
crossvalue = [8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
              25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 
              48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]
hardsploit.set_cross_wiring(crossvalue)

if sys.argv[0] != "nofirmware":
    (hardsploit.load_firmware("UART"))


uart = HardsploitUART(baud_rate=57600, word_width=8, use_parity_bit=0, parity_type=0, nb_stop_bits=1,
                      idle_line_level=1, hardsploit_api=hardsploit)


print(f"\nEffective baudrate {uart._baud_rate} \n")

t1 = threading.Thread(target=uart_custom_read)
# Thread will die when main thread ends
t1.daemon = True

help_menu()
menu()

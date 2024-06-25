

import sys
import pathlib
import inspect
from colorama import Fore, Style
from hardsploit.core import HardsploitAPI

hardsploit_package = pathlib.Path(pathlib.Path(inspect.getfile(lambda: None)).parents[1])
sys.path.append(hardsploit_package.resolve().as_posix())


def callback_progress(percent, start_time, end_time):
    print(f"Upload of FPGA firmware in progress : {percent}")



HardsploitAPI.callbackProgress = callback_progress

hardsploit = HardsploitAPI()
hardsploit.load_firmware("I2C")
print(Fore.GREEN + Style.BRIGHT + "Firmware load successfully!")

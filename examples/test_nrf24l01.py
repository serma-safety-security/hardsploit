from sys import argv
from time import time

from hardsploit.core import HardsploitAPI, HardsploitError, HardsploitUtils
from hardsploit.modules import NRF24L01


def callback_info(receive_data):
    print(receive_data + "\n")


def callback_data(receive_data):
    if receive_data:
        print(f"received {len(receive_data)}")
        print(f"{receive_data=}")
    else:
        print("[!] No data received")


def callback_speed_of_transfert(receive_data):
    print(f"Speed : {receive_data}")


def callback_progress(percent, start_time, end_time):
    print(f"\r\x1b[31mUpload of FPGA firmware in progress : {percent}%\x1b[0m")


print(f"Number of hardsploit detected :{HardsploitUtils.get_number_of_board_available()}")

HardsploitAPI.callbackProgress = callback_progress

hardsploit = HardsploitAPI()
hardsploit.get_all_versions()

if len(argv) <= 1 or argv[1] != "nofirmware":
    hardsploit.load_firmware("SPI")

# HARDSPLOIT                    NRF24L01
# SPI_CLK   (pin A0)      ===>    SCK
# SPI_CS    (pin A1)      ===>    CSN
# SPI_MOSI  (pin A2)      ===>    MOSI
# SPI_MISO  (pin A3)      ===>    MISO
# SPI_PULSE (pin A4)      ===>    CE

try:
    nrf = NRF24L01(hardsploit)
    if nrf.reset():
        # You need to change your channel and you address
        nrf.init_drone(7, [0x66, 0x88, 0x68, 0x68, 0x68])
    else:
        raise RuntimeError("NRF24L01 not found")
except HardsploitError.HardsploitNotFound:
    print("[!] Hardsploit not found")
except HardsploitError.USBError:
    print("[!] USB Error")

print("NRF24L01+")
print("Press p to program hardsploit")
print("Press r to receive")
print("Press t to transmit")
print("Press s to sniff all channel")

while True:
    try:
        ch = input("> ")
    except (KeyboardInterrupt, EOFError):
        print("Finished")
        break

    if ch == "t":
        datat = [23, 4, 97, 100, 109, 105, 110, 0, 0, 24, 99, 36, 163, 0, 0, 128]
        # datat = [23, 3, 0x41, 0x42, 0x43, 0x44, 0x45, 0xFF, 0xFF, 24, 99, 36, 163, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE3, 0x19]
        nrf.send(datat)

        for i in range(19):
            datat = [0, 0, 128, 128, 128, 0, 0, 0, 0, 24, 99, 36, 163, 0, 0, 128]
            nrf.send(datat)
        print("Done")

    elif ch == "r":
        print("Listen :")
        while True:
            data = nrf.read()
            if len(data) > 0:
                print(f"{data=}")
    elif ch == "s":
        print("Sniffing in progress :")
        for channel in range(126):
            nrf.flush_tx()
            nrf.flush_rx()
            nrf.change_channel(channel)
            timeoutValue = 1  # timeout in seconds

            # read during 1 second to verify if something is available
            timeBegin = time()
            while True:
                if time() - timeBegin > timeoutValue:
                    print(f"Nothing to read on channel {channel} after {timeoutValue} second")
                    break
                data = nrf.read()
                if len(data) > 0:
                    print(f"Something is available on channel {channel}, you need to read this channel now")
                    print(f"{data=}")
                    break

    elif ch == "p":
        hardsploit.load_firmware("SPI")

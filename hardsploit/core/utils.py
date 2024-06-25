import usb.core
from colorama import Fore, Style


class HardsploitUtils:

    # Obtain low byte of a word
    # * +word+:: 16 bit word
    # Return low byte of the word
    @staticmethod
    def low_byte(word):
        return int(word) & 0xFF

    # Obtain high byte of a word
    # * +word+:: 16 bit word
    # Return high byte of the word
    @staticmethod
    def high_byte(word):
        return (int(word) & 0xFF00) >> 8

    # Obtain high byte of a word
    # * +lByte+:: low byte
    # * +hByte+:: high byte
    # Return 16 bits integer concatenate with low and high bytes
    @staticmethod
    def bytes_to_int(l_byte, h_byte):
        return l_byte + (h_byte << 8)

    @staticmethod
    def reverse_bit(byte):
        return int('{:08b}'.format(byte)[::-1], 2)

    # Obtain the number of hardsploit connected to PC
    # Return number
    @staticmethod
    def get_number_of_board_available():
        return len(list(usb.core.find(idVendor=0x0483, idProduct=0xFFFF, find_all=True)))

    # Return only odd or even tab elements
    @staticmethod
    def odds_and_evens(tab, return_odds):
        return tab[1::2] if return_odds else tab[::2]

    # call back
    @staticmethod
    def console_progress(percent, start_time, end_time, debug=False):
        from hardsploit.core import HardsploitAPI
        if debug:
            print(Fore.MAGENTA)
            print("Progress : {}%  Start@ {}  Stop@ {}".format(percent, start_time, end_time))
            print("Elasped time {} sec".format(round(end_time - start_time, 4)))
            print(Style.RESET_ALL)
        else:
            HardsploitAPI.callbackProgress(percent, start_time, end_time)

    @staticmethod
    def console_data(receive_data, debug=False):
        from hardsploit.core import HardsploitAPI
        if debug:
            if receive_data:
                print("received {}".format(len(receive_data)))
                print(receive_data)
            else:
                print("ISSUE BECAUSE DATA IS NIL")
        else:
            HardsploitAPI.callbackData(receive_data)

    @staticmethod
    def console_speed(value, debug=False):
        if debug:
            print(Fore.GREEN + value + Style.RESET_ALL)

    @staticmethod
    def console_info(value, debug=False):
        if debug:
            print(Fore.CYAN + value + Style.RESET_ALL)

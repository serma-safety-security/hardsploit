from dataclasses import dataclass


class HardsploitConstant:

    # Obtain signal id
    # Params:
    # +signal+:: Name of signal you want to obtain ud
    @staticmethod
    def get_signal_id(signal):

        wires = {"A0": 0, "A1": 1, "A2": 2, "A3": 3, "A4": 4, "A5": 5, "A6": 6, "A7": 7, "A8": 8, "A9": 9, "A10": 10,
                 "A11": 11, "A12": 12, "A13": 13, "A14": 14, "A15": 15, "A16": 16, "A17": 17, "A18": 18, "A19": 19,
                 "A20": 20, "A21": 21, "A22": 22, "A23": 23, "A24": 24, "A25": 25, "A26": 26, "A27": 27, "A28": 28,
                 "A29": 29, "A30": 30, "A31": 31, "D0": 32, "D1": 33, "D2": 34, "D3": 35, "D4": 36, "D5": 37, "D6": 38,
                 "D7": 39, "D8": 40, "D9": 41, "D10": 42, "D11": 43, "D12": 44, "D13": 45, "D14": 46, "D15": 47,
                 "RST": 48, "CE": 49, "OE": 50, "WE": 51, "PARA_CLK": 52, "WP": 53, "ADV": 54, "SPI_CLK": 0, "CS": 1,
                 "MOSI": 2, "MISO": 3, "PULSE": 4, "I2C_CLK": 0, "SDA": 1, "TX": 0, "RX": 1, "SWD_CLK": 0, "SWD_IO": 1,
                 "CAN_RX": 0, "CAN_TX": 1}

        # Parallel module

        # SPI module

        # I2C module

        # UART module

        # SWD module

        # CAN module

        return wires[signal]

    @staticmethod
    @dataclass
    class UsbCommand:
        GREEN_LED = 0
        RED_LED = 1
        LOOPBACK = 2
        ERASE_FIRMWARE = 3
        WRITE_PAGE_FIRMWARE = 4
        READ_PAGE_FIRMWARE = 5
        READ_ID_FLASH = 6
        START_FPGA = 7
        STOP_FPGA = 8
        FPGA_COMMAND = 9
        FPGA_DATA = 10
        STOP_FPGA_DATA = 11
        START_FPGA_DATA = 12
        GET_SERIAL_NUMBER = 13
        GET_VERSION_NUMBER = 14
        VCP_ERROR = 0xFFFF

    @staticmethod
    @dataclass
    class I2C:
        KHZ_100 = 0
        KHZ_400 = 1
        KHZ_1000 = 2
        KHZ_40 = 3

    @staticmethod
    @dataclass
    class SPISniffer:
        MOSI = 1
        MISO = 2
        MISO_MOSI = 3

    @staticmethod
    @dataclass
    class USB:
        OUT_ENDPOINT = 0x02
        IN_ENDPOINT = 0x81
        USB_TRAME_SIZE = 8192

    @staticmethod
    @dataclass
    class VERSION:
        API = "2.0.0"

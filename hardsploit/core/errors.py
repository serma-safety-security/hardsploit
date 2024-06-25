class HardsploitError:

    @staticmethod
    class HardsploitNotFound(Exception):
        def __init__(self):
            super().__init__("HARDSPLOIT NOT FOUND")

    @staticmethod
    class ApiCrossWiring(Exception):
        def __init__(self):
            super().__init__("The crossWiring array must be a 64 items array")

    @staticmethod
    class ApiInvalidFirmware(Exception):
        def __init__(self):
            super().__init__("invalid firmware! please choose one of ()")

    @staticmethod
    class ApiScannerWrongPinNumber(Exception):
        def __init__(self):
            super().__init__("You need to connect more thant pins needed by the module 2 for swd, 2 for I2C etc")

    @staticmethod
    class FileIssue(Exception):
        def __init__(self):
            super().__init__("Issue with file")

    @staticmethod
    class I2CWrongSpeed(Exception):
        def __init__(self):
            super().__init__("Unknown speed, speed must be KHZ_100 = 0, KHZ_400 = 1,KHZ_1000 = 2")

    @staticmethod
    class SPIWrongPulse(Exception):
        def __init__(self):
            super().__init__("Wrong, Pulse must be 0 or 1")

    @staticmethod
    class SPIWrongSpeed(Exception):
        def __init__(self):
            super().__init__("Speed must be between 3 and 255")

    @staticmethod
    class SPIWrongMode(Exception):
        def __init__(self):
            super().__init__("Mode must be between 0 and 3")

    @staticmethod
    class SPIWrongPayloadSize(Exception):
        def __init__(self):
            super().__init__("Size of the data need to be less than 4000")

    @staticmethod
    class WrongStartAddress(Exception):
        def __init__(self):
            super().__init__("Start address can't be negative and not more than size max - 1")

    @staticmethod
    class SpiError(Exception):
        def __init__(self):
            super().__init__("Error during SPI processing")

    @staticmethod
    class USBPacketIsTooLarge(Exception):
        def __init__(self):
            super().__init__("USB_PACKET_IS_TOO_LARGE")

    @staticmethod
    class USBError(Exception):
        def __init__(self):
            super().__init__("USB ERROR")

    @staticmethod
    class SWDError(Exception):
        def __init__(self):
            super().__init__("SWD ERROR, WAIT, FAUL, ACK or something like that")

    @staticmethod
    class UARTWrongSettings(Exception):
        def __init__(self):
            super().__init__("Wrong UART settings")

    @staticmethod
    class UARTWrongTxPayloadSize(Exception):
        def __init__(self):
            super().__init__("Wrong TX payload size")

    @staticmethod
    class UARTWrongPayloadSize(Exception):
        def __init__(self):
            super().__init__("Size of the data need to be less than 4000")

    @staticmethod
    class CANWrongSettings (Exception):
        def __init__(self):
            super().__init__("Wrong CAN settings")

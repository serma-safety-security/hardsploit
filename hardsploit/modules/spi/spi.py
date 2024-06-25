import os
import time
import math
from hardsploit.core import HardsploitError, HardsploitUtils, HardsploitConstant


class HardsploitSPI:

    def __init__(self, speed, mode, hardsploit_api):
        self.__speed = speed
        self.__mode = mode
        self.__api = hardsploit_api
        self.__pulse = 0

    @property
    def pulse(self):
        return self.__pulse

    @pulse.setter
    def pulse(self, pulse):
        if pulse in (0, 1):
            self.__pulse = pulse
            self.spi_set_settings()  # Send an Empty array to validate the value of pulse
        else:
            raise HardsploitError.SPIWrongPulse

    @property
    def speed(self):
        return self.__speed

    @speed.setter
    def speed(self, speed):
        if (speed <= 2) or (speed > 256):
            raise HardsploitError.SPIWrongSpeed
        else:
            self.__speed = speed

    @property
    def mode(self):
        return self.__mode

    @mode.setter
    def mode(self, mode):
        if (mode < 0) or (mode > 3):
            raise HardsploitError.SPIWrongMode
        else:
            self.__mode = mode

    def spi_set_settings(self):
        packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND), 0x50,
                  ((self.pulse & 1) << 2) or (self.mode & 3), self.speed]

        try:
            self.__api.send_packet(packet)
        except:
            raise HardsploitError.USBError

    #  SPI interact
    # * +payload+:: Byte array want to send
    # * Return SPI data received
    def spi_interact(self, payload):
        if len(payload) > 4000:
            raise HardsploitError.SPIWrongPayloadSize

        packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND), 0x50,
                  int(bin((self.pulse & 0b1) << 2) or (self.mode & 3), 2), self.speed]

        # concat 2 arrays
        packet += payload  # Add data
        # print(f"packet {packet}")
        # remove header (4 bytes   2 for size 2 for type of command)
        return self.__api.send_and_receive_data(packet, 1000)[4:]

    # Spi generic Import * +writeSpiCommand+:: The write command most of the time 0x02 * +startAddress+:: Start
    # address (included) * +pageSize+:: Size of page * +memorySize+:: Size max of memory in byte (important,
    # to calculate automatically the number of byte to set address) * +saveFile+:: File contain data *
    # +writePageLatency+:: Time to wait after each page written * +enableWriteSpiCommand+:: Enable write command most
    # of the time 0x06 * +clearSpiCommand+:: Bulk erase command most of the time 0x60  chip eraseTime *
    # +clearChipTime+:: Time to erase entire the memory (bulk erase) in case of flash memory, 240 seconds for a 512Mb
    # expansion memory and  13 seconds for a 16Mb Micron memory, see the datasheet * +isFLASH+:: True if it is a Flash
    # memory (add clear content)
    def spi_generic_import(self, start_address, page_size, memory_size, data_file, write_spi_command, write_page_latency,
                           enable_write_spi_command, clear_spi_command, clear_chip_time, is_flash):

        f = open(data_file, 'rb')
        size_file = os.path.getsize(data_file)

        if start_address < 0 or start_address > memory_size - 1:
            raise HardsploitError.WrongStartAddress

        if 0 >= page_size > 2048:
            raise TypeError("pageSize need to be greater than 0 and less than 2048")

        number_of_byte_address = math.ceil(((math.floor(math.log(memory_size - 1, 2))) + 1) / 8.0)
        if number_of_byte_address > 4:
            raise TypeError("Size max must be less than 2^32 about 4Gb")

        if number_of_byte_address <= 0:
            raise TypeError("There is an issue with calculating of number of byte needed")

        # if flash memory we need to erase it before and wait enough
        # time (erase cycle time in datasheet) or polling status register
        if is_flash:
            self.spi_interact(payload=[clear_spi_command])
            time.sleep(clear_chip_time)

        start_time = time.time()
        packet_size = page_size
        number_complet_packet = int(math.floor(size_file / packet_size))
        size_last_packet = size_file % packet_size

        # SEND the first complete trame
        for i in range(number_complet_packet):
            # Enable write latch
            self.spi_interact(payload=[enable_write_spi_command])
            packet = self.generate_spi_write_command(
                number_of_byte_address=number_of_byte_address,
                write_spi_command=write_spi_command,
                start_address=i * packet_size + start_address,
                data=list(filter(lambda x: x, f.read(packet_size)))
            )

            temp = self.spi_interact(payload=packet)
            # Remove header, result of read command and numberOfByte Address too
            if len(packet) != len(temp):
                raise HardsploitError.SpiError
            print(str(100 * (i + 1) / (number_complet_packet + (0 if size_last_packet == 0 else 1))))
            HardsploitUtils.console_progress(percent=100 * (i + 1) / (number_complet_packet +
                                                                      (0 if size_last_packet == 0 else 1)),
                                             start_time=start_time, end_time=time.time())
            # if too many error when write increase because we need to wait to write a full page
            time.sleep(write_page_latency)

        if size_last_packet > 0:
            # Enable write latch
            self.spi_interact(payload=[enable_write_spi_command])
            packet = self.generate_spi_write_command(number_of_byte_address=number_of_byte_address,
                                                     write_spi_command=write_spi_command,
                                                     start_address=number_complet_packet * packet_size + start_address,
                                                     data=list(filter(lambda x: x, f.read(packet_size))))

            temp = self.spi_interact(payload=packet)
            # Remove header, result of write command and numberOfByte Address too
            if len(packet) != len(temp):
                raise HardsploitError.SpiError

            # Send 100% in case of last packet
            HardsploitUtils.console_progress(percent=100, start_time=start_time, end_time=time.time())

        delta = time.time() - start_time
        HardsploitUtils.console_speed("Write in {} sec".format(round(delta, 4)))

    # Spi generic dump
    # * +readSpiCommand+:: The read command
    # * +startAddress+:: Start address (included)
    # * +stopAddress+:: Stop address (included)
    # * +sizeMax+:: Size max of memory (important to calculate automatically the number of byte to set address)
    def spi_generic_dump(self, read_spi_command, start_address, stop_address, size_max):
        if start_address < 0 or start_address > size_max - 1:
            raise TypeError("Start address can't be negative and not more than size max - 1")

        if stop_address < 0 or stop_address > size_max - 1:
            raise TypeError("Stop address can't be negative and not more than size max-1 because start at 0")

        if stop_address < start_address:
            raise TypeError("Stop address need to be greater than start address")

        number_of_byte_address = math.ceil((math.floor(math.log(size_max - 1, 2)) + 1) / 8.0)
        if number_of_byte_address > 4:
            raise TypeError("Size max must be less than 2^32 about 4Gb")

        if number_of_byte_address <= 0:
            raise TypeError("There is an issue with calculating of number of byte needed")

        # Start time
        start_time = time.time()
        packet_size = 4000 - number_of_byte_address - 1
        number_complet_packet = math.floor((stop_address - start_address + 1) / packet_size)
        size_last_packet = (stop_address - start_address + 1) % packet_size

        # SEND the first complete trame
        for i in range(number_complet_packet):
            packet = self.generate_spi_read_command(
                number_of_byte_address=number_of_byte_address, read_spi_command=read_spi_command,
                start_address=i * packet_size + start_address, size=packet_size)
            try:
                temp = self.spi_interact(payload=packet)
            except:
                raise HardsploitError.USBError

            # Remove header, result of read command and numberOfByte Address too
            HardsploitUtils.console_data(temp[number_of_byte_address + 1:])
            HardsploitUtils.console_progress(
                percent=100 * (i + 1) / (number_complet_packet + (0 if size_last_packet == 0 else 1)),
                start_time=start_time, end_time=time.time())

        if size_last_packet > 0:
            packet = self.generate_spi_read_command(
                number_of_byte_address=number_of_byte_address, read_spi_command=read_spi_command,
                start_address=number_complet_packet * packet_size + start_address, size=size_last_packet)
            temp = self.spi_interact(payload=packet)
            # Remove header, result of read command and numberOfByte Address too
            HardsploitUtils.console_data(temp[number_of_byte_address + 1:])
            try:
                HardsploitUtils.console_progress(percent=100, start_time=start_time, end_time=time.time())
            except:
                raise HardsploitError.USBError

            delta = time.time() - start_time
            HardsploitUtils.console_speed("Write in {} sec".format(round(delta, 4)))

    @staticmethod
    def generate_spi_read_command(number_of_byte_address, read_spi_command, start_address, size):
        packet = [read_spi_command]
        if number_of_byte_address == 1:
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        elif number_of_byte_address == 2:
            packet.append(((start_address & 0x0000FF00) >> 8))  # AddStart1
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        elif number_of_byte_address == 3:
            packet.append(((start_address & 0x00FF0000) >> 16))  # AddStart2
            packet.append(((start_address & 0x0000FF00) >> 8))  # AddStart1
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        elif number_of_byte_address == 4:
            packet.append(((start_address & 0xFF000000) >> 24))  # AddStart3
            packet.append(((start_address & 0x00FF0000) >> 16))  # AddStart2
            packet.append(((start_address & 0x0000FF00) >> 8))  # AddStart1
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        else:
            raise TypeError("Issue in generate_spi_read_command function when parse number of byte address")

        # put N dummy byte to read size data
        packet += [0] * size
        if len(packet) > 4000:
            raise TypeError("Too many byte to send in spi mode not more than 4000 is needed")

        return packet

    @staticmethod
    def generate_spi_write_command(number_of_byte_address, write_spi_command, start_address, data):
        packet = [write_spi_command]
        if number_of_byte_address == 1:
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        elif number_of_byte_address == 2:
            packet.append(((start_address & 0x0000FF00) >> 8))  # AddStart1
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        elif number_of_byte_address == 3:
            packet.append(((start_address & 0x00FF0000) >> 16))  # AddStart2
            packet.append(((start_address & 0x0000FF00) >> 8))  # AddStart1
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        elif number_of_byte_address == 4:
            packet.append(((start_address & 0xFF000000) >> 24))  # AddStart3
            packet.append(((start_address & 0x00FF0000) >> 16))  # AddStart2
            packet.append(((start_address & 0x0000FF00) >> 8))  # AddStart1
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        else:
            raise TypeError("Issue in generate_spi_write_command function when parse number of byte address")

        # Push data to write
        packet += data
        if len(packet) > 4000:
            raise TypeError("Too many byte to send in spi mode not more than 4000 is needed")

        return packet

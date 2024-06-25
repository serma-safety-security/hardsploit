import math
import os
import time

from hardsploit.core import HardsploitConstant, HardsploitUtils, HardsploitError


class HardsploitI2c:

    # attr_accessor :speed
    # attr_reader :device_version

    # * +speed+:: I2C::KHZ_40  ,  I2C::KHZ_100  , 	I2C::KHZ_400 ,	I2C::KHZ_1000
    def __init__(self, speed, hardsploit_api):
        self._speed = speed
        self._api = hardsploit_api

    @property
    def speed(self):
        return self._speed

    @speed.setter
    def speed(self, speed):
        if speed not in [HardsploitConstant.I2C.KHZ_40, HardsploitConstant.I2C.KHZ_100, HardsploitConstant.I2C.KHZ_400,
                         HardsploitConstant.I2C.KHZ_1000]:
            raise HardsploitError.I2CWrongSpeed
        self._speed = speed

    # Interact with I2C bus
    # * +payload+:: payload to send
    def i2c_interact(self, payload):

        if len(payload) > 4000:
            raise TypeError("Size of the data need to be less than 4000")

        packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.FPGA_COMMAND), 0x50, self.speed]

        # concat 2 arrays
        packet += payload  # Add data
        # puts "Payload : #{payload}"

        # remove header (4 bytes   2 for size 2 for type of command)
        print(f"payload: {packet}")
        return self._api.send_and_receive_data(packet, 2000)[4:]

    # Start I2C scan to find addresses
    # * +speed+:: I2C::KHZ_100  , 	I2C::KHZ_400 ,	I2C::KHZ_1000
    # * Return  An array 256 value for each address if 0 not present if 1 present
    def i2c_scan(self):
        if 0 > self.speed > 3:
            raise HardsploitError.I2CWrongSpeed

        array_i2c_scan = []
        return_scan = []

        # we want scan just read address it is a partial scan (fastest)
        for i in range(1, 256, 2):
            array_i2c_scan.append(HardsploitUtils.low_byte(word=1))  # Count Low  Byte
            array_i2c_scan.append(HardsploitUtils.high_byte(word=1))  # Count High Byte
            array_i2c_scan.append(i)

        result_scan = self.i2c_interact(payload=array_i2c_scan)
        if len(result_scan) != 256:
            result_scan = []

        for i in range(0, len(result_scan) - 1, 2):
            # Check if ACK_ERROR
            if result_scan[i] == 1:
                return_scan.append(1)  # For write
                return_scan.append(1)  # For read
            else:
                return_scan.append(0)  # For write
                return_scan.append(0)  # For read

        return return_scan

    # Interact with I2C bus
    # * +speed+:: I2C::KHZ_100  , 	I2C::KHZ_400 ,	I2C::KHZ_1000
    # * +i2cBaseAddress+:: I2C base address / Write address  (8bits)
    # * +startAddress+:: Start address (included)
    # * +stopAddress+:: Stop address (included)
    # * +sizeMax+:: Size max of memory (important to calculate automaticly the number of byte to set address)
    def i2c_generic_dump(self, i2c_base_address, start_address, stop_address, size_max):
        if start_address < 0 or start_address > size_max - 1:
            raise TypeError("Start address can't be negative and not more than size max - 1")

        if stop_address < 0 or stop_address > size_max - 1:
            raise TypeError("Stop address can't be negative and not more than size max-1 because start at 0")

        if stop_address <= start_address:
            raise TypeError("Stop address need to be greater than start address")

        number_of_byte_address = math.ceil((math.floor(math.log(size_max - 1, 2)) + 1) / 8.0)
        if number_of_byte_address > 4:
            raise TypeError("Size max must be less than 2^32 about 4Gb")

        if number_of_byte_address <= 0:
            raise TypeError("There is an issue with calculating of number of byte needed")

        start_time = time.time()
        packet_size = 2000 - number_of_byte_address - 1
        number_complet_packet = int(math.floor((stop_address - start_address + 1) / packet_size))
        size_last_packet = (stop_address - start_address + 1) % packet_size

        # SEND the first complete trame
        for i in range(number_complet_packet):
            packet = self.generate_i2c_read_command(
                i2c_base_address=i2c_base_address,
                number_of_byte_address=number_of_byte_address + start_address,
                start_address=i * packet_size,
                size=packet_size)

            # Remove header, result of read command and numberOfByte Address too
            HardsploitUtils.console_data(self.process_dump_i2c_result(self.i2c_interact(payload=packet)))
            HardsploitUtils.console_progress(
                percent=100 * (i + 1) / (number_complet_packet + (0 if size_last_packet == 0 else 1)),
                start_time=start_time,
                end_time=time.time())

        if size_last_packet > 0:
            packet = self.generate_i2c_read_command(
                i2c_base_address=i2c_base_address,
                number_of_byte_address=number_of_byte_address,
                start_address=number_complet_packet * packet_size + start_address,
                size=size_last_packet)

            # Remove header, result of read command and numberOfByte Address too
            HardsploitUtils.console_data(self.process_dump_i2c_result(self.i2c_interact(payload=packet)))
            HardsploitUtils.console_progress(
                percent=100,
                start_time=start_time,
                end_time=time.time())

        delta = time.time() - start_time
        HardsploitUtils.console_speed(f"Write in {round(delta, 4)} sec")

    # For the moment only with EEPROM (not need to erase or activate write)
    def i2c_generic_import(self, i2c_base_address, start_address, page_size,
                           memory_size, data_file, write_page_latency):

        start_time = time.time()
        try:
            f = open(data_file, 'rb')
            size_file = os.path.getsize(data_file)
        except FileNotFoundError:
            raise TypeError(f"File {data_file} not found.  Aborting")

        if start_address < 0 or start_address > memory_size - 1:
            raise HardsploitError.WrongStartAddress

        if 0 >= page_size > 1024:
            raise TypeError("pageSize need to be greater than 0 and less than 1024")

        number_of_byte_address = math.ceil((math.floor(math.log(memory_size - 1, 2)) + 1) / 8.0)
        if number_of_byte_address > 4:
            raise TypeError("Size max must be less than 2^32 about 4Gb")

        if number_of_byte_address <= 0:
            raise TypeError("There is an issue with calculating of number of byte needed")

        packet_size = page_size
        number_complet_packet = math.ceil(math.floor(size_file / packet_size))
        size_last_packet = size_file % packet_size

        # SEND the first complete trame
        for i in range(number_complet_packet):
            packet = self.generate_i2c_write_command(
                i2c_base_address=i2c_base_address,
                number_of_byte_address=number_of_byte_address,
                start_address=i * packet_size,
                data=list(filter(lambda x: x, f.read(packet_size))))

            # Remove header, result of read command and numberOfByte Address too
            self.process_import_i2c_result(self.i2c_interact(payload=packet))

            HardsploitUtils.console_progress(
                percent=100 * (i + 1) / (number_complet_packet + (0 if size_last_packet == 0 else 1)),
                start_time=start_time,
                end_time=time.time())
            # if too many error when write increase because we need to wait to write a full page
            time.sleep(write_page_latency)

        if size_last_packet > 0:
            packet = self.generate_i2c_write_command(
                i2c_base_address=i2c_base_address,
                number_of_byte_address=number_of_byte_address,
                start_address=number_complet_packet * packet_size + start_address,
                data=list(filter(lambda x: x, f.read(packet_size))))

            # Remove header, result of read command and numberOfByte Address too
            self.process_import_i2c_result(self.i2c_interact(payload=packet))

            HardsploitUtils.console_progress(
                percent=100,
                start_time=start_time,
                end_time=time.time())

        delta = time.time() - start_time
        HardsploitUtils.console_speed("Write in #{} sec".format(round(delta, 4)))

    def find(self, number_of_connected_pin_from_a0):
        posibility = self._api.all_posibility(number_of_connected_pin_from_a0=number_of_connected_pin_from_a0,
                                              number_of_signals_for_bus=2)

        compare_tab = [1] * 256
        for item in posibility:
            current_wiring = 0
            for value in item:
                current_wiring += 2 ** value
                self._api.set_wiring_leds(value=current_wiring)

            for i in range(63 - len(item)):
                item.append(i + number_of_connected_pin_from_a0)
                self._api.set_cross_wiring(value=item)

            try:
                tab = self.i2c_scan()
                if 1 in tab and tab != compare_tab:
                    return item
            except Exception as msg:
                print(msg)

    @staticmethod
    def process_import_i2c_result(packet):
        result = []
        for i in range(0, len(packet), 2):
            if packet[i] != 0:
                raise TypeError("Error in I2C transaction (NACK), write failed")
            elif packet[i] == 0:  # Write ACK
                pass
        # Do nothing,don't save write ack

        return result

    @staticmethod
    def process_dump_i2c_result(packet):
        result = []
        for i in range(0, len(packet), 2):
            if packet[i] == 1:  # Read ACK
                # Save read data
                result.append(packet[i + 1])
            elif packet[i] == 0:  # Write ACK
                pass  # Do nothing,don't save write ack
            else:
                raise TypeError("Error in I2C transaction, I2C export seems to be wrong")

        return result

    @staticmethod
    def generate_i2c_write_command(i2c_base_address, number_of_byte_address, start_address, data):

        packet = [HardsploitUtils.low_byte(word=number_of_byte_address + len(data)),
                  HardsploitUtils.high_byte(word=number_of_byte_address + len(data)), i2c_base_address]

        # Push write command

        if number_of_byte_address == 1:
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        elif number_of_byte_address == 2:
            packet.append(((start_address & 0x0000FF00) >> 8))  # AddStart1
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart
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
            raise TypeError("Issue in generate_i2c_write_command function when parse number of byte address")

        # Push data to write
        packet += data
        return packet

    @staticmethod
    def generate_i2c_read_command(i2c_base_address, number_of_byte_address, start_address, size):

        packet = [HardsploitUtils.low_byte(word=number_of_byte_address),
                  HardsploitUtils.high_byte(word=number_of_byte_address), i2c_base_address]

        # Push write command for start address

        if number_of_byte_address == 1:
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart0
        elif number_of_byte_address == 2:
            packet.append(((start_address & 0x0000FF00) >> 8))  # AddStart1
            packet.append(((start_address & 0x000000FF) >> 0))  # AddStart
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
            raise TypeError("Issue in generate_i2c_write_command function when parse number of byte address")

        # Push read command to read size data
        packet.append(HardsploitUtils.low_byte(word=size))  # size of read command
        packet.append(HardsploitUtils.high_byte(word=size))  # size of read command
        packet.append(i2c_base_address + 1)  # push read address

        return packet

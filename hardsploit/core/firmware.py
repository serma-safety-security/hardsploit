from pathlib import Path
from datetime import datetime
import os
import time
import inspect

from hardsploit.core import HardsploitUSBCommunication, HardsploitUtils, HardsploitConstant, \
    HardsploitError


class HardsploitFirmware(HardsploitUSBCommunication):

    def load_firmware(self, firmware):

        base_path = Path(Path(inspect.getfile(lambda: None)).parents[1], 'firmwares/fpga/').resolve()
        if self.dfu:
            if firmware == 'uC':
                os.system(f"dfu-util -D 0483:df11 -a 0 -s 0x08000000 -R --download {Path(base_path.parents[1], 'firmwares/uc/HARDSPLOIT_FIRMWARE_UC.bin')}")
            else:
                raise HardsploitError.ApiInvalidFirmware
        else:
            if firmware == 'I2C':
                firmware_path = Path(base_path, 'i2c/I2C_INTERACT/HARDSPLOIT_FIRMWARE_FPGA_I2C_INTERACT.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'I2C_SNIFFER':
                firmware_path = Path(base_path, 'i2c/I2C_SNIFFER/HARDSPLOIT_FIRMWARE_FPGA_I2C_SNIFFER.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'SPI':
                firmware_path = Path(base_path, 'spi/SPI_INTERACT/HARDSPLOIT_FIRMWARE_FPGA_SPI_INTERACT.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'SPI_SNIFFER':
                firmware_path = Path(base_path, 'spi/SPI_SNIFFER/HARDSPLOIT_FIRMWARE_FPGA_SPI_SNIFFER.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'PARALLEL':
                firmware_path = Path(base_path, 'parallel/NO_MUX_PARALLEL_MEMORY/HARDSPLOIT_FIRMWARE_FPGA_NO_MUX_PARALLEL_MEMORY.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'MUX_PARALLEL':
                firmware_path = Path(base_path, 'parallel/MUX_PARALLEL_MEMORY/HARDSPLOIT_FIRMWARE_FPGA_MUX_PARALLEL_MEMORY.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'SWD':
                firmware_path = Path(base_path, 'swd/SWD_INTERACT/HARDSPLOIT_FIRMWARE_FPGA_SWD_INTERACT.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'UART':
                firmware_path = Path(base_path, 'uart/UART_INTERACT/HARDSPLOIT_FIRMWARE_FPGA_UART_INTERACT.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'CAN':
                firmware_path = Path(base_path, 'can/CAN_SNIFFER/HARDSPLOIT_FIRMWARE_FPGA_CAN_SNIFFER.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            elif firmware == 'CAN_INTERACT':
                firmware_path = Path(base_path, 'can/CAN_INTERACT/HARDSPLOIT_FIRMWARE_FPGA_CAN_INTERACT.rpd')
                self.upload_firmware(path_firmware=firmware_path, check_firmware=False)
            else:
                raise HardsploitError.ApiInvalidFirmware
        
    # Wait to receive data
    # * +pathFirmware+:: path of rpd file (vhdl)
    # * +checkFirmware+:: boolean if check is needed (recommended false, in case issue true to check)
    # Return true if firmware write == firmware read (slow because read the firmware for check)
    def upload_firmware(self, path_firmware, check_firmware):
        self.stop_fpga()
        self.erase_firmware()

        firmware_write = self.write_firmware(path_firmware)  # return array of bytes write

        if check_firmware:
            firmware_read = self.read_firmware(len(firmware_write))  # return array of bytes read
            self.start_fpga()
            time.sleep(1)
            return firmware_write == firmware_read
        else:
            self.start_fpga()
            time.sleep(1)
            return True

    # protected
    def erase_firmware(self):
        usb_packet = [HardsploitUtils.low_byte(word=4),
                      HardsploitUtils.high_byte(word=4),
                      HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.ERASE_FIRMWARE),
                      HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.ERASE_FIRMWARE)]

        HardsploitUtils.console_info("Start to erase Firmware\n")
        time1 = time.time()

        # Timeout very high to detect the end of erasing
        self.send_and_receive_data(usb_packet, 15000)

        time2 = time.time()
        delta = time2 - time1
        HardsploitUtils.console_speed("Firmware erased in {} sec\n\n".format(round(delta, 4)))

    # Just path of file and wait. is a blocking function until firmware has been uploaded
    def write_firmware(self, file_path):
        t1 = time.time()
        HardsploitUtils.console_info(value="Upload firmware in progress\n")

        f = open(file=file_path, mode="rb")
        file = bytearray(f.read())  # string to array byte
        print("Date of last modification of the firmware {}".format(datetime.fromtimestamp(Path(file_path).stat().st_mtime)))

        HardsploitUtils.console_info("FIRMWARE Write {} bytes\n".format(len(file)))

        nb_full_page = len(file) / 256
        nb_last_byte = len(file) % 256
        nb_full_packet = int(nb_full_page / 31)
        nb_last_page_packet = int(nb_full_page % 31)
        nb_suppress_bytes_at_last = 256 - nb_last_byte
        # complete last page with the last alone byte ( without full page)
        if nb_last_byte > 0:
            for i in range(nb_suppress_bytes_at_last - 1):
                file += 0xFF
            nb_full_page = nb_full_page + 1

            # recalculating packet after complete half page to a full page
            nb_full_packet = int(nb_full_page / 31)
            nb_last_page_packet = int(nb_full_page % 31)
        else:
            nb_suppress_bytes_at_last = 0

        HardsploitUtils.console_info("REAL Write {} bytes\n".format(len(file)))

        # Now only full page but maybe a half packet
        # Prepare the full packet (31 pages of 256 byte each)
        for ipacket in range(int(nb_full_packet) - 1):
            usb_packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.WRITE_PAGE_FIRMWARE),
                          HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.WRITE_PAGE_FIRMWARE),
                          HardsploitUtils.low_byte(word=ipacket * 31), HardsploitUtils.high_byte(word=ipacket * 31), 31]

            start = ipacket * 31 * 256
            stop = (ipacket + 1) * 31 * 256  # array start at index = 0

            for iFile in range(start, stop):
                usb_packet.append(HardsploitUtils.reverse_bit(file[iFile]))

            percent = ipacket * 100 / (nb_full_packet - 1)
            try:
                self.send_packet(usb_packet)
                HardsploitUtils.console_speed("UPLOAD AT  : {} / {} ({}) %\n".format(ipacket, nb_full_packet - 1, percent))
                HardsploitUtils.console_progress(percent=percent, start_time=t1, end_time=time.time())
            except:
                raise HardsploitError.USBError

        # Prepare the last packet with the rest of data
        if nb_last_page_packet > 0:
            usb_packet = [0, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.WRITE_PAGE_FIRMWARE),
                          HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.WRITE_PAGE_FIRMWARE)]

            if nb_full_packet == 0:
                usb_packet.append(HardsploitUtils.low_byte(word=nb_full_packet * 31))  # low byte Nb of the first page
                usb_packet.append(HardsploitUtils.high_byte(word=nb_full_packet * 31))  # high byte Nb of the first page
            else:
                usb_packet.append(HardsploitUtils.low_byte(word=nb_full_packet * 31 + 1))  # low byte Nb of the first page
                usb_packet.append(HardsploitUtils.high_byte(word=nb_full_packet * 31 + 1))  # high byte Nb of the first page

            usb_packet.append(nb_last_page_packet)  # nb of page < 31

            start = nb_full_packet * 31 * 256
            stop = nb_full_packet * 31 * 256 + nb_last_page_packet * 256 - 1

            for iFile in range(int(start), int(stop)):
                # inverted LSB MSB
                usb_packet.append(HardsploitUtils.reverse_bit(file[iFile]))

            try:
                self.send_packet(usb_packet)
                HardsploitUtils.console_speed("UPLOAD AT  :  100 %\n")
                HardsploitUtils.console_progress(percent=100, start_time=t1, end_time=time.time())
            except:
                raise HardsploitError.USBError

        t2 = time.time()
        delta = t2 - t1
        HardsploitUtils.console_speed("FIRMWARE WAS WRITTEN in {} sec\n".format(round(delta, 4)))
        file.pop(nb_suppress_bytes_at_last)
        return str(file)

    # Read firmware
    def read_firmware(self, size):
        global received_data
        HardsploitUtils.console_speed("START READ FIRMWARE \n")
        read_firmware = []
        t1 = time.time()

        nb_full_page = size / 256
        nb_last_byte = size % 256

        nb_full_packet = nb_full_page / 31
        nb_last_page_packet = nb_full_page % 31

        if nb_last_byte > 0:
            nb_suppress_bytes_at_last = 256 - nb_last_byte

            nb_full_page = nb_full_page + 1
            nb_full_packet = nb_full_page / 31
            nb_last_page_packet = nb_full_page % 31
        else:
            nb_suppress_bytes_at_last = 0

        for ipacket in range(nb_full_packet - 1):
            usb_packet = [7, 0, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.READ_PAGE_FIRMWARE),
                          HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.READ_PAGE_FIRMWARE),
                          HardsploitUtils.low_byte(word=ipacket * 31), HardsploitUtils.high_byte(word=ipacket * 31), 31]

            received_data = self.send_and_receive_data(usb_packet, 3000)
            # remove header
            received_data = received_data.drop(7)

            # reverse byte
            temp_data = None
            for x in received_data:
                temp_data += HardsploitUtils.reverse_bit(x)
            received_data = temp_data

            read_firmware.append(received_data)
            if nb_full_packet == 1:
                HardsploitUtils.console_speed("READ AT  : 1 / 2 50 %\n")
                HardsploitUtils.console_progress(percent=50, start_time=t1, end_time=time.time())
            else:
                percent = ipacket * 100 / (nb_full_packet - 1)
                HardsploitUtils.console_speed("READ AT  : {} / {} ({} %) \n".format(ipacket, nb_full_packet - 1, percent))
                HardsploitUtils.console_progress(percent=percent, start_time=t1, end_time=time.time())

        # Prepare the last packet with the rest of data
        if nb_last_page_packet > 0:
            usb_packet = [0, 7, HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.READ_PAGE_FIRMWARE),
                          HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.READ_PAGE_FIRMWARE)]

            # Increase nb of page to add the last byte
            if nb_full_packet == 0:
                usb_packet.append(HardsploitUtils.low_byte(word=nb_full_packet * 31))  # low byte Nb of the first page
                usb_packet.append(HardsploitUtils.high_byte(word=nb_full_packet * 31))  # high byte Nb of the first page
            else:
                usb_packet.append(HardsploitUtils.low_byte(word=nb_full_packet * 31 + 1))  # low byte Nb of the first page
                usb_packet.append(HardsploitUtils.high_byte(word=nb_full_packet * 31 + 1))  # high byte Nb of the first page

            usb_packet.append(nb_last_page_packet)

            received_data = self.send_and_receive_data(usb_packet, 15000)
            # remove header
            received_data = received_data.drop(7)
            # reverse byte
            temp_data = None
            for x in received_data:
                temp_data += HardsploitUtils.reverse_bit(x)
            received_data = temp_data

        read_firmware.append(received_data)
        HardsploitUtils.console_speed("READ AT 100%\n")

        # remove a fake byte at last of reading just for transmitting
        read_firmware.pop(nb_suppress_bytes_at_last)

        t2 = time.time()
        delta = t2 - t1
        HardsploitUtils.console_speed("READ FIRMWARE FINISH  in {} sec\n".format(round(delta, 4)))
        return read_firmware

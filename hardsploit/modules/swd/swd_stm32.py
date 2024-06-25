import math
from time import time

from hardsploit.core import HardsploitUtils
from .swd_mem_ap import SwdMemAp


class SwdSTM32:

    def __init__(self, debug_port):
        self.ahb = SwdMemAp(debug_port, 0)
        self.debug_port = debug_port

    def halt(self):
        # halt the processor core
        self.ahb.write_word(0xE000EDF0, 0xA05F0003)

    def unhalt(self):
        # unhalt the processor core
        self.ahb.write_word(0xE000EDF0, 0xA05F0000)

    def sys_reset(self):
        # restart the processor and peripherals
        self.ahb.write_word(0xE000ED0C, 0x05FA0004)

    def flash_read(self, address, size):
        data = []
        # Read a word of 32bits (4 Bytes in same time)
        size = size / 4
        # Chunk to 1k block for SWD
        # ARM_debug_interface_v5 Automatic address increment is only guaranteed to operate on the bottom 10-bits  of the
        # address held in the TAR. Auto address incrementing of bit [10] and beyond is
        # IMPLEMENTATION DEFINED. This means that auto address incrementing at a 1KB boundary
        # is IMPLEMENTATION DEFINED

        # But for hardsploit max 8192  so chuck to  1k due to swd limitation

        packet_size = 1024
        number_complet_packet = math.floor(size / packet_size)
        size_last_packet = size % packet_size
        start_time = time()
        # number_complet_packet
        for i in range(number_complet_packet):
            data += self.ahb.read_block(i * 4 * packet_size + address, packet_size)
            # puts "Read #{packet_size} KB : #{i}"
            HardsploitUtils.console_progress(percent=100 * (i + 1) / (number_complet_packet +
                                                                      (0 if size_last_packet == 0 else 1)),
                                             start_time=start_time, end_time=time())
        # Last partial packet
        if size_last_packet > 0:
            data += self.ahb.read_block(number_complet_packet * 4 * packet_size + address, size_last_packet)
            # puts "Read last packet : #{size_last_packet} packet of 4 bytes"
            HardsploitUtils.console_progress(percent=100, start_time=start_time, end_time=time())
        return data

    def flash_write(self, address, data):
        # Chunk to 1k block for SWD
        packet_size = 1024  # 1024
        number_complet_packet = math.floor(len(data) / packet_size)
        size_last_packet = len(data) % packet_size
        start_time = time()
        # ahb.csw(2, 1) # 16-bit packed incrementing addressing
        # number_complet_packet
        for i in range(number_complet_packet):
            self.ahb.write_block(address + i * packet_size, data[i * packet_size: i * packet_size + packet_size])
            # puts "Write #{packet_size} KB : #{i}"
            HardsploitUtils.console_progress(percent=100 * (i + 1) / (number_complet_packet +
                                                                      (0 if size_last_packet == 0 else 1)),
                                             start_time=start_time, end_time=time())
        # Last partial packet
        if size_last_packet > 0:
            self.ahb.write_block(address + number_complet_packet * packet_size,
                                 data[number_complet_packet * packet_size:
                                      number_complet_packet * packet_size + size_last_packet])
            # puts "Write last packet : #{size_last_packet} packet"
            HardsploitUtils.console_progress(percent=100, start_time=start_time, end_time=time())
        self.ahb.csw(1, 2)  # set to default 32-bit incrementing addressing

    def flash_unlock(self):
        # unlock main flash
        self.ahb.write_word(0x40022004, 0x45670123)
        self.ahb.write_word(0x40022004, 0xCDEF89AB)

    def flash_erase(self):
        HardsploitUtils.console_info("Flash unlock")
        self.flash_unlock()
        # start the mass erase
        self.ahb.write_word(0x40022010, 0x00000204)
        self.ahb.write_word(0x40022010, 0x00000244)
        # check the BSY flag
        while (self.ahb.read_word(0x4002200C) & 1) == 1:
            HardsploitUtils.console_info("waiting for erase completion...")
        self.ahb.write_word(0x40022010, 0x00000200)
        HardsploitUtils.console_info("Finish unlock flash")

    def flash_program(self):
        self.ahb.write_word(0x40022010, 0x00000201)

    def flash_program_end(self):
        self.ahb.write_word(0x40022010, 0x00000200)

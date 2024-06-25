import time
from array import array

from .swd_debug import SwdDebugPort
from .swd_stm32 import SwdSTM32
from hardsploit.core import HardsploitUtils, HardsploitError


class HardsploitSWD:
    # attr_accessor :debugPort
    # attr_accessor :stm32
    DCRDR = 0xE000EDF8  # address of Debug Core Register Data Register
    DCRSR = 0xE000EDF4  # address of Debug Core Register Selector Register

    def __init__(self, memory_start_address, memory_size_address, cpu_id_address, device_id_address, hardsploit_api):
        self._api = hardsploit_api
        self.memory_start_address = (int(memory_start_address, 16))
        self.memory_size_address = (int(memory_size_address, 16))
        self.cpu_id_address = (int(cpu_id_address, 16))
        self.device_id_address = (int(device_id_address, 16))
        self.stm32 = None

    def read_regs(self):
        # halt the target before read register
        self.stop()
        self.stm32.ahb.csw(1, 2)
        print(self.read_mem8(0x1FFFF7E0, 2))
        # p self.stm32.ahb.readWord(@memory_size_address).to_s(16)
        for i in range(36):
            # Write DCRSR address into TAR register
            # Write core register index Rn into DRW register.
            self.write_mem32(HardsploitSWD.DCRSR, [i, 0, 0, 0])
            # self.stm32.ahb.writeWord( DCRSR,i)

            # Write DCRDR address into TAR register.
            # Read core register value from DRW register.
            # value = self.stm32.ahb.readWord( DCRDR)
            result = self.read_mem32(HardsploitSWD.DCRDR, 1)
            value = result[0] + (result[1] << 8) + (result[2] << 16) + (result[3] << 24)
            print(f"R{i} {hex(value)[2:]}")

    def stop(self):
        # halt the processor core
        self.write_mem32(0xE000EDF0, [0x03, 0x00, 0x5F, 0xA0])

    def start(self):
        # start the processor core
        self.write_mem32(0xE000EDF0, [0x00, 0x00, 0x5F, 0xA0])

    def obtain_codes(self):
        self.debug_port = SwdDebugPort(self)
        self.stm32 = SwdSTM32(self.debug_port)
        #  Cortex M4 0x410FC241
        #  Cortex M3 0x411FC231
        self.reset_swd()
        # code = {
        #   :DebugPortId  => @debugPort.idcode,
        #   :AccessPortId => self.stm32.ahb.idcode,
        #   :CpuId 				=> self.stm32.ahb.readWord(@cpu_id_address),
        # 	:DeviceId 		=> self.stm32.ahb.readWord(@device_id_address)
        # }

        code = {
            'DebugPortId': self.debug_port.idcode(),
            'AccessPortId': self.stm32.ahb.idcode(),
            'CpuId': self.stm32.ahb.read_word(self.cpu_id_address)
        }
        return code

    def find(self, number_of_connected_pin_from_a0):
        posibility = self._api.allPosibility(
            numberOfConnectedPinFromA0=number_of_connected_pin_from_a0, numberOfSignalsForBus=2)
        for item in posibility:
            current_wiring = 0
            for value in item:
                current_wiring += 2 ** value
            self._api.setWiringLeds(value=current_wiring)
            for i in range(63 - len(item)):
                item.append(i + number_of_connected_pin_from_a0)
            self._api.setCrossWiring(value=item)
            try:
                self.obtain_codes()
                return item
            except Exception as msg:
                print(msg)

    def write_flash(self, path):
        self.obtain_codes()
        file = open(path, 'br')
        data_write = file.read()
        HardsploitUtils.console_info("Halting Processor")
        self.stm32.halt()
        HardsploitUtils.console_info("Erasing Flash")
        self.stm32.flashUnlock()
        self.stm32.flashErase()
        HardsploitUtils.console_info("Programming Flash")
        self.stm32.flashProgram()
        time_start = time.time()
        self.stm32.flashWrite(self.memory_start_address, data_write)
        time_end = time.time() - time_start
        HardsploitUtils.console_info(f"Write {round(len(data_write) / time_end), 2}Bytes/s {len(data_write)}Bytes "
                                     f"in {round(time_end, 4)} s")
        self.stm32.flashProgramEnd()
        HardsploitUtils.console_info("Resetting")
        self.stm32.sysReset()
        HardsploitUtils.console_info("Start")
        self.stm32.unhalt()

    def erase_flash(self):
        self.obtain_codes()
        HardsploitUtils.console_info('Erase')
        self.stm32.flash_erase()

    def dump_flash(self, path):
        self.obtain_codes()
        self.stm32.halt()
        flash_size = (self.stm32.ahb.read_word(self.memory_size_address) & 0xFFFF)
        HardsploitUtils.console_info(f"Flash size : {flash_size} KB")
        HardsploitUtils.console_info("Dump flash")
        time_start = time.time()
        data = self.stm32.flash_read(self.memory_start_address, (flash_size * 1024))
        time_end = time.time() - time_start
        HardsploitUtils.console_speed(f"DUMP {round(len(data) / time_end, 2)} Bytes/s {len(data)}Bytes in "
                                      f"{round(time_end, 4)} s")
        f = open(path, "wb")
        f.write(bytes(data))
        f.close()
        HardsploitUtils.console_info("Finish dump")

    def read_mem8(self, address, size):
        packet = self._api.prepare_packet()
        packet.append(0xAA)  # Read mode
        packet.append(HardsploitUtils.low_byte(word=size))
        packet.append(HardsploitUtils.high_byte(word=size))
        packet.append((address & 0xFF) >> 0)
        packet.append((address & 0xFF00) >> 8)
        packet.append((address & 0xFF0000) >> 16)
        packet.append((address & 0xFF000000) >> 24)

        # --[2:0]	Size
        # 	--Size of access field:
        # 	--b000 = 8 bits
        # 	--b001 = 16 bits
        # 	--b010 = 32 bits
        # 	--b011-111 are reserved.
        # 	--Reset value: b000
        #
        # 	--[5:4]	AddrInc
        # 	--0b00 = auto increment off.
        # 	--0b01 = increment single. Single transfer from corresponding byte lane.
        # 	--0b10 = increment packed.[b]
        # 	--0b11 = reserved. No transfer.
        # 	--Size of address increment is defined by the Size field [2:0].
        # 	--Reset value: 0b00.
        packet.append(0b00010000)  # single 8 bits auto increment
        result = self._api.send_and_receive_data(packet, 1000)
        # Check if result is an array
        if not isinstance(result, array):
            print("Error during reading  timeout or ACK issue")
            raise HardsploitError.SWDError()
        # raise HardsploitAPI::ERROR::SWD_ERROR,"We need to receive #{size  } and we received #{result.size-4}"	 unless (result.size-4) == size # Receive all data
        return result[4:]

    def read_mem32(self, address, size):
        packet = self._api.prepare_packet()
        packet.append(0xAA)  # Read mode
        packet.append(HardsploitUtils.low_byte(word=size))
        packet.append(HardsploitUtils.high_byte(word=size))
        packet.append((address & 0xFF) >> 0)
        packet.append((address & 0xFF00) >> 8)
        packet.append((address & 0xFF0000) >> 16)
        packet.append((address & 0xFF000000) >> 24)

        # --[2:0]	Size
        # 	--Size of access field:
        # 	--b000 = 8 bits
        # 	--b001 = 16 bits
        # 	--b010 = 32 bits
        # 	--b011-111 are reserved.
        # 	--Reset value: b000
        #
        # 	--[5:4]	AddrInc
        # 	--0b00 = auto increment off.
        # 	--0b01 = increment single. Single transfer from corresponding byte lane.
        # 	--0b10 = increment packed.[b]
        # 	--0b11 = reserved. No transfer.
        # 	--Size of address increment is defined by the Size field [2:0].
        # 	--Reset value: 0b00.
        packet.append(0b00010010)  # single 32 bits auto increment

        result = self._api.send_and_receive_data(packet, 1000)
        # Check if result is an array
        if not isinstance(result, array):
            print("Error during reading  timeout or ACK issue")
            raise HardsploitError.SWDError()
        # Receive all data
        if (len(result) - 4) / 4 != size:
            print(f"We need to receive {size + 4} and we received {len(result)}")
            raise HardsploitError.SWDError()
        return result[4:]

    def write_mem32(self, address, data):
        if len(data) > 2000:
            raise "Too many data (> 2000)"
        packet = self._api.prepare_packet()
        packet.append(0xBB)  # Write ap
        packet.append((address & 0xFF) >> 0)
        packet.append((address & 0xFF00) >> 8)
        packet.append((address & 0xFF0000) >> 16)
        packet.append((address & 0xFF000000) >> 24)

        # --[2:0]	Size
        # 	--Size of access field:
        # 	--b000 = 8 bits
        # 	--b001 = 16 bits
        # 	--b010 = 32 bits
        # 	--b011-111 are reserved.
        # 	--Reset value: b000
        #
        # 	--[5:4]	AddrInc
        # 	--0b00 = auto increment off.
        # 	--0b01 = increment single. Single transfer from corresponding byte lane.
        # 	--0b10 = increment packed.[b]
        # 	--0b11 = reserved. No transfer.
        # 	--Size of address increment is defined by the Size field [2:0].
        # 	--Reset value: 0b00.
        packet.append(0b00010010)  # single 32 bits auto increment needed to write in flash

        packet += data
        result = self._api.send_and_receive_data(packet, 1000)
        # Check if result is an array
        if not isinstance(result, array):
            print("Error during writing, timeout")
            raise HardsploitError.SWDError
        if len(result) != 5:
            print("Error during writing")
            raise HardsploitError.SWDError
        if result[4] == 1:
            return True
        if result[4] == 2:
            print("WAIT response")
            raise HardsploitError.SWDError
        if result[4] == 4:
            print("FAULT response")
            raise HardsploitError.SWDError
        print(f"WRITE ERROR {result[4]}")
        raise HardsploitError.SWDError

    def write_mem8(self, address, data):
        if len(data) > 2000:
            raise "Too many data (> 2000)"
        packet = self._api.prepare_packet()
        packet.append(0xBB)  # Write ap
        packet.append((address & 0xFF) >> 0)
        packet.append((address & 0xFF00) >> 8)
        packet.append((address & 0xFF0000) >> 16)
        packet.append((address & 0xFF000000) >> 24)

        # --[2:0]	Size
        # 	--Size of access field:
        # 	--b000 = 8 bits
        # 	--b001 = 16 bits
        # 	--b010 = 32 bits
        # 	--b011-111 are reserved.
        # 	--Reset value: b000
        #
        # 	--[5:4]	AddrInc
        # 	--0b00 = auto increment off.
        # 	--0b01 = increment single. Single transfer from corresponding byte lane.
        # 	--0b10 = increment packed.[b]
        # 	--0b11 = reserved. No transfer.
        # 	--Size of address increment is defined by the Size field [2:0].
        # 	--Reset value: 0b00.
        packet.append(0b00010000)  # single 8 bits auto increment needed to write in flash
        packet += data

        packet.append(0)  # Dummy need to be improved in VHDL

        result = self._api.send_and_receive_data(packet, 1000)
        # Check if result is an array
        if not isinstance(result, array):
            print("Error during writing, timeout")
            raise HardsploitError.SWDError
        if len(result) != 5:
            print("Error during writing")
            raise HardsploitError.SWDError
        if result[4] == 1:
            return True
        if result[4] == 2:
            print("WAIT response")
            raise HardsploitError.SWDError
        if result[4] == 4:
            print("FAULT response")
            raise HardsploitError.SWDError
        print(f"WRITE ERROR {result[4]}")
        raise HardsploitError.SWDError

    def write_mem16_packed(self, address, data):
        if len(data) > 2000:
            raise "Too many data (> 2000)"
        packet = self._api.prepare_packet()
        packet.append(0xBB)  # Write ap
        packet.append((address & 0xFF) >> 0)
        packet.append((address & 0xFF00) >> 8)
        packet.append((address & 0xFF0000) >> 16)
        packet.append((address & 0xFF000000) >> 24)

        # --[2:0]	Size
        # 	--Size of access field:
        # 	--b000 = 8 bits
        # 	--b001 = 16 bits
        # 	--b010 = 32 bits
        # 	--b011-111 are reserved.
        # 	--Reset value: b000
        #
        # 	--[5:4]	AddrInc
        # 	--0b00 = auto increment off.
        # 	--0b01 = increment single. Single transfer from corresponding byte lane.
        # 	--0b10 = increment packed.[b]
        # 	--0b11 = reserved. No transfer.
        # 	--Size of address increment is defined by the Size field [2:0].
        # 	--Reset value: 0b00.
        packet.append(0b00100001)  # packet 16 bits auto increment need to write in flash

        packet += data
        result = self._api.send_and_receive_data(packet, 1000)
        # Check if result is an array
        if not isinstance(result, array):
            print("Error during writing, timeout")
            raise HardsploitError.SWDError
        if len(result) != 5:
            print("Error during writing")
            raise HardsploitError.SWDError
        if result[4] == 1:
            return True
        if result[4] == 2:
            print("WAIT response")
            raise HardsploitError.SWDError
        if result[4] == 4:
            print("FAULT response")
            raise HardsploitError.SWDError
        print(f"WRITE ERROR {result[4]}")
        raise HardsploitError.SWDError

    def write_swd(self, ap, register, data):
        data = int(data)
        packet = self._api.prepare_packet()
        packet.append(0x10)  # Write mode
        packet.append(self.calc_opcode(ap, register, False))  # Send Request
        packet.append((data & 0xFF) >> 0)
        packet.append((data & 0xFF00) >> 8)
        packet.append((data & 0xFF0000) >> 16)
        packet.append((data & 0xFF000000) >> 24)
        result = self._api.send_and_receive_data(packet, 1000)
        # Check if result is an array
        if not isinstance(result, array):
            print("Error during writing, timeout")
            raise HardsploitError.SWDError
        if len(result) != 5:
            print("Error during writing")
            raise HardsploitError.SWDError
        if result[4] == 1:
            return True
        if result[4] == 2:
            print("WAIT response")
            raise HardsploitError.SWDError
        if result[4] == 4:
            print("FAULT response")
            raise HardsploitError.SWDError
        print(f"WRITE ERROR {result[4]}")
        raise HardsploitError.SWDError

    def read_swd(self, ap, register):
        packet = self._api.prepare_packet()
        packet.append(0x11)  # Read mode
        packet.append(self.calc_opcode(ap, register, True))  # Send Request
        result = self._api.send_and_receive_data(packet, 1000)
        # Check if result is an array
        if not isinstance(result, array):
            print("Error during writing, timeout")
            raise HardsploitError.SWDError
        if len(result) == 5:
            print(f"Read error ACK : {result[4]}")
            raise HardsploitError.SWDError
        if len(result) == 8:  # Receive read + 4bytes for header
            return (result[7] << 24) + (result[6] << 16) + (result[5] << 8) + result[4]
        print("Error during reading")
        raise HardsploitError.SWDError

    # Return array with 1 byte for ACK
    # Return 32bits integer for data read here is Core ID
    # Raise if error
    def reset_swd(self):
        packet = self._api.prepare_packet()
        packet.append(0x00)  # Reset mode
        result = self._api.send_and_receive_data(packet, 1000)
        # Check if result is an array
        if not isinstance(result, array):
            print("Error during reading ICCODE timeout")
            raise HardsploitError.SWDError
        if len(result) == 8:
            return (result[7] << 24) + (result[6] << 16) + (result[5] << 8) + result[4]
        if len(result) != 5:  # reveice ACK
            print(f"Reset error ACK {result[4]}")
            raise HardsploitError.SWDError
        print("Error during reading ICCODE result != 4")
        raise HardsploitError.SWDError

    @staticmethod
    def calc_opcode(ap, register, read):
        opcode = 0x00
        opcode |= (0x40 if ap else 0x00)
        opcode |= (0x20 if read else 0x00)
        # Addr AP DP  bit 2..3
        opcode = opcode | ((register & 0x01) << 4) | ((register & 0x02) << 2)
        # 0x78 mask to take only read ap and register to process parity bit
        opcode = opcode | ((1 if bin(opcode & 0x78)[2:].count('1') % 2 else 0) << 2)
        opcode = opcode | 0x81  # Start and Park Bit
        return opcode

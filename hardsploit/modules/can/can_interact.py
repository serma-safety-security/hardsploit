import math

from hardsploit.core import HardsploitError


class HardsploitCANInteract:

    def __init__(self, baud_rate, crc_poly, crc_type, id, n_std_ext, cmde, n_data_request, data, hardsploit_api):

        self._baud_rate = baud_rate
        self._crc_poly = crc_poly
        self._crc_type = crc_type
        self._id = id
        self._nStd_Ext = n_std_ext
        self._cmde = cmde
        self._nData_Request = n_data_request
        self._data = data
        self._payload = []
        self._api = hardsploit_api

    @property
    def baud_rate(self):
        return 150000000 / self._baud_rate

    @baud_rate.setter
    def baud_rate(self, baud_rate):
        if not baud_rate:
            self._baud_rate = 0
        elif (baud_rate >= 2400) and (baud_rate <= 2000000):
            self._baud_rate = 150000000 / baud_rate - 1
        else:
            raise HardsploitError.CANWrongSettings  # Change error settings

    @property
    def crc_poly(self):
        return self._crc_poly

    @crc_poly.setter
    def crc_poly(self, crc_poly):
        self._crc_poly = crc_poly

    @property
    def crc_type(self):
        return self._crc_type

    @crc_type.setter
    def crc_type(self, crc_type):
        self._crc_type = crc_type

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        self._id = id

    @property
    def n_std_ext(self):
        return self._nStd_Ext

    @n_std_ext.setter
    def n_std_ext(self, n_std_ext):
        self._nStd_Ext = n_std_ext

    @property
    def cmde(self):
        return self._cmde

    @cmde.setter
    def cmde(self, cmde):
        self._cmde = cmde

    @property
    def n_data_request(self):
        return self._nData_Request

    @n_data_request.setter
    def n_data_request(self, n_data_request):
        self._nData_Request = n_data_request

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        self._data = data

    def crc_check(self, complete_frame):
        modif_frame = complete_frame
        for i in range(len(complete_frame) - 15):
            if complete_frame[i] == 1:
                modif_frame[i] = complete_frame[i] ^ ((self._crc_poly & 0x8000) >> 15)
                modif_frame[i + 1] = complete_frame[i] ^ ((self._crc_poly & 0x4000) >> 14)
                modif_frame[i + 2] = complete_frame[i] ^ ((self._crc_poly & 0x2000) >> 13)
                modif_frame[i + 3] = complete_frame[i] ^ ((self._crc_poly & 0x1000) >> 12)
                modif_frame[i + 4] = complete_frame[i] ^ ((self._crc_poly & 0x0800) >> 11)
                modif_frame[i + 5] = complete_frame[i] ^ ((self._crc_poly & 0x0400) >> 10)
                modif_frame[i + 6] = complete_frame[i] ^ ((self._crc_poly & 0x0200) >> 9)
                modif_frame[i + 7] = complete_frame[i] ^ ((self._crc_poly & 0x0100) >> 8)
                modif_frame[i + 8] = complete_frame[i] ^ ((self._crc_poly & 0x0080) >> 7)
                modif_frame[i + 9] = complete_frame[i] ^ ((self._crc_poly & 0x0040) >> 6)
                modif_frame[i + 10] = complete_frame[i] ^ ((self._crc_poly & 0x0020) >> 5)
                modif_frame[i + 11] = complete_frame[i] ^ ((self._crc_poly & 0x0010) >> 4)
                modif_frame[i + 12] = complete_frame[i] ^ ((self._crc_poly & 0x0008) >> 3)
                modif_frame[i + 13] = complete_frame[i] ^ ((self._crc_poly & 0x0004) >> 2)
                modif_frame[i + 14] = complete_frame[i] ^ ((self._crc_poly & 0x0002) >> 1)
                modif_frame[i + 15] = complete_frame[i] ^ ((self._crc_poly & 0x0001) >> 0)

        valid_crc = 0
        for i in range(len(modif_frame) - 1):
            if modif_frame[i] == 1:
                valid_crc = 1
        return valid_crc

    @staticmethod
    def fill_can_frame(tab, data):
        tab.append((data & 0x80) >> 7)
        tab.append((data & 0x40) >> 6)
        tab.append((data & 0x20) >> 5)
        tab.append((data & 0x10) >> 4)
        tab.append((data & 0x08) >> 3)
        tab.append((data & 0x04) >> 2)
        tab.append((data & 0x02) >> 1)
        tab.append((data & 0x01) >> 0)

    def data_formating(self, id, n_std_ext, cmde, n_data_request, data):  # data is a tab with 8 elements
        complete_frame = []
        size_frame = 0
        if n_std_ext == 1:
            complete_frame.append(0)  # Start bit
            complete_frame.append((id & 0x10000000) >> 28)
            complete_frame.append((id & 0x08000000) >> 27)
            complete_frame.append((id & 0x04000000) >> 26)
            complete_frame.append((id & 0x02000000) >> 25)
            complete_frame.append((id & 0x01000000) >> 24)
            complete_frame.append((id & 0x00800000) >> 23)
            complete_frame.append((id & 0x00400000) >> 22)
            complete_frame.append((id & 0x00200000) >> 21)
            complete_frame.append((id & 0x00100000) >> 20)
            complete_frame.append((id & 0x00080000) >> 19)
            complete_frame.append((id & 0x00040000) >> 18)
            complete_frame.append(1)
            complete_frame.append(n_std_ext)
            complete_frame.append((id & 0x00020000) >> 17)
            complete_frame.append((id & 0x00010000) >> 16)
            complete_frame.append((id & 0x00008000) >> 15)
            complete_frame.append((id & 0x00004000) >> 14)
            complete_frame.append((id & 0x00002000) >> 13)
            complete_frame.append((id & 0x00001000) >> 12)
            complete_frame.append((id & 0x00000800) >> 11)
            complete_frame.append((id & 0x00000400) >> 10)
            complete_frame.append((id & 0x00000200) >> 9)
            complete_frame.append((id & 0x00000100) >> 8)
            complete_frame.append((id & 0x00000080) >> 7)
            complete_frame.append((id & 0x00000040) >> 6)
            complete_frame.append((id & 0x00000020) >> 5)
            complete_frame.append((id & 0x00000010) >> 4)
            complete_frame.append((id & 0x00000008) >> 3)
            complete_frame.append((id & 0x00000004) >> 2)
            complete_frame.append((id & 0x00000002) >> 1)
            complete_frame.append((id & 0x00000001) >> 0)
            complete_frame.append(n_data_request)
            complete_frame.append(0)
            complete_frame.append(0)
            complete_frame.append((cmde & 0x8) >> 3)
            complete_frame.append((cmde & 0x4) >> 2)
            complete_frame.append((cmde & 0x2) >> 1)
            complete_frame.append((cmde & 0x1) >> 0)
            size_frame = 37
            if n_data_request == 0:
                if cmde >= 1:
                    self.fill_can_frame(complete_frame, data[0])
                    size_frame = 45
                    if cmde >= 2:
                        self.fill_can_frame(complete_frame, data[1])
                        size_frame = 53
                        if cmde >= 3:
                            self.fill_can_frame(complete_frame, data[2])
                            size_frame = 61
                            if cmde >= 4:
                                self.fill_can_frame(complete_frame, data[3])
                                size_frame = 69
                                if cmde >= 5:
                                    self.fill_can_frame(complete_frame, data[4])
                                    size_frame = 77
                                    if cmde >= 6:
                                        self.fill_can_frame(complete_frame, data[5])
                                        size_frame = 85
                                        if cmde >= 7:
                                            self.fill_can_frame(complete_frame, data[6])
                                            size_frame = 93
                                            if cmde >= 8:
                                                self.fill_can_frame(complete_frame, data[7])
                                                size_frame = 101
        elif n_std_ext == 0:  # Standard ID
            complete_frame.append(0)  # Start bit
            complete_frame.append((id & 0x00000400) >> 10)
            complete_frame.append((id & 0x00000200) >> 9)
            complete_frame.append((id & 0x00000100) >> 8)
            complete_frame.append((id & 0x00000080) >> 7)
            complete_frame.append((id & 0x00000040) >> 6)
            complete_frame.append((id & 0x00000020) >> 5)
            complete_frame.append((id & 0x00000010) >> 4)
            complete_frame.append((id & 0x00000008) >> 3)
            complete_frame.append((id & 0x00000004) >> 2)
            complete_frame.append((id & 0x00000002) >> 1)
            complete_frame.append((id & 0x00000001) >> 0)
            complete_frame.append(n_data_request)
            complete_frame.append(n_std_ext)
            complete_frame.append(0)
            complete_frame.append((cmde & 0x8) >> 3)
            complete_frame.append((cmde & 0x4) >> 2)
            complete_frame.append((cmde & 0x2) >> 1)
            complete_frame.append((cmde & 0x1) >> 0)
            size_frame = 18
            if n_data_request == 0:
                if cmde >= 1:
                    self.fill_can_frame(complete_frame, data[0])
                    size_frame = 26
                    if cmde >= 2:
                        self.fill_can_frame(complete_frame, data[1])
                        size_frame = 34
                        if cmde >= 3:
                            self.fill_can_frame(complete_frame, data[2])
                            size_frame = 42
                            if cmde >= 4:
                                self.fill_can_frame(complete_frame, data[3])
                                size_frame = 50
                                if cmde >= 5:
                                    self.fill_can_frame(complete_frame, data[4])
                                    size_frame = 58
                                    if cmde >= 6:
                                        self.fill_can_frame(complete_frame, data[5])
                                        size_frame = 66
                                        if cmde >= 7:
                                            self.fill_can_frame(complete_frame, data[6])
                                            size_frame = 74
                                            if cmde >= 8:
                                                self.fill_can_frame(complete_frame, data[7])
                                                size_frame = 82
        size_frame += 1
        return [complete_frame, size_frame]

    @staticmethod
    def crc_calculation(complete_frame, crc_type, size_frame, crc_poly):  # Modifier
        modif_frame = complete_frame
        for i in range(crc_type - 2):
            modif_frame.append(0)

        count = (size_frame - 1) + (crc_type - 1)
        size_frame = size_frame + (crc_type - 1)
        modif_frame = list(reversed(modif_frame))
        while count >= 15:
            if modif_frame[count] == 1:
                modif_frame[count] = modif_frame[count] ^ ((crc_poly & 0x8000) >> 15)
                modif_frame[count - 1] = modif_frame[count - 1] ^ ((crc_poly & 0x4000) >> 14)
                modif_frame[count - 2] = modif_frame[count - 2] ^ ((crc_poly & 0x2000) >> 13)
                modif_frame[count - 3] = modif_frame[count - 3] ^ ((crc_poly & 0x1000) >> 12)
                modif_frame[count - 4] = modif_frame[count - 4] ^ ((crc_poly & 0x0800) >> 11)
                modif_frame[count - 5] = modif_frame[count - 5] ^ ((crc_poly & 0x0400) >> 10)
                modif_frame[count - 6] = modif_frame[count - 6] ^ ((crc_poly & 0x0200) >> 9)
                modif_frame[count - 7] = modif_frame[count - 7] ^ ((crc_poly & 0x0100) >> 8)
                modif_frame[count - 8] = modif_frame[count - 8] ^ ((crc_poly & 0x0080) >> 7)
                modif_frame[count - 9] = modif_frame[count - 9] ^ ((crc_poly & 0x0040) >> 6)
                modif_frame[count - 10] = modif_frame[count - 10] ^ ((crc_poly & 0x0020) >> 5)
                modif_frame[count - 11] = modif_frame[count - 11] ^ ((crc_poly & 0x0010) >> 4)
                modif_frame[count - 12] = modif_frame[count - 12] ^ ((crc_poly & 0x0008) >> 3)
                modif_frame[count - 13] = modif_frame[count - 13] ^ ((crc_poly & 0x0004) >> 2)
                modif_frame[count - 14] = modif_frame[count - 14] ^ ((crc_poly & 0x0002) >> 1)
                modif_frame[count - 15] = modif_frame[count - 15] ^ ((crc_poly & 0x0001) >> 0)
            count -= 1
        while (crc_type - 2) >= 0:
            complete_frame.append(modif_frame[crc_type - 2])
            crc_type -= 1
        return [complete_frame, size_frame]

    @staticmethod
    def add_stuff_bytes(frame, size_frame):
        size_stuff = size_frame
        for i in range(size_frame - 1 - 4):
            if (frame[i] & frame[i + 1] & frame[i + 2] & frame[i + 3] & frame[i + 4]) == 1:
                frame.insert(i + 5, 0)
                size_stuff += 1
            elif (frame[i] | frame[i + 1] | frame[i + 2] | frame[i + 3] | frame[i + 4]) == 0:
                frame.insert(i + 5, 1)
                size_stuff += 1
        return [frame, size_stuff]

    @staticmethod
    def prepare_frame(frame, size_frame_bits):
        frame_bytes = []
        value = 0
        size_frame_bytes = math.floor(float(size_frame_bits) / 8.0)
        size = 0
        for i in range(size_frame_bytes - 1):
            frame_bytes.append(
                (frame[i * 8 + 0] & 0x01) + ((frame[i * 8 + 1] & 0x01) << 1) + ((frame[i * 8 + 2] & 0x01) << 2) + (
                            (frame[i * 8 + 3] & 0x01) << 3) + ((frame[i * 8 + 4] & 0x01) << 4) + (
                            (frame[i * 8 + 5] & 0x01) << 5) + ((frame[i * 8 + 6] & 0x01) << 6) + (
                            (frame[i * 8 + 7] & 0x01) << 7))
            size = (i + 1) * 8
        if size_frame_bits - size == 0:
            return [frame_bytes, size_frame_bytes]
        else:
            size_frame_bits = size_frame_bits - size - 1
            for i in range(size_frame_bits):
                value = value + ((frame[size_frame_bytes * 8 + i] & 0x01) << i)
            frame_bytes.append(value)
            return [frame_bytes, size_frame_bytes + 1]

    # result = [ERROR | size_frame (bits) | frame into bytes]
    def formating_table(self, result):
        result_format = []
        received_frame = []
        valid_id = None
        if result[0] == 0x55:
            if result[1] == 0x00:
                result_format.append(0x00)
                return result_format
            else:
                size_byte = math.ceil(float(result[1]) / 8.0)
                for i in range(size_byte):
                    received_frame.append((result[i + 2] & 0x80) >> 7)
                    received_frame.append((result[i + 2] & 0x40) >> 6)
                    received_frame.append((result[i + 2] & 0x20) >> 5)
                    received_frame.append((result[i + 2] & 0x10) >> 4)
                    received_frame.append((result[i + 2] & 0x08) >> 3)
                    received_frame.append((result[i + 2] & 0x04) >> 2)
                    received_frame.append((result[i + 2] & 0x02) >> 1)
                    received_frame.append((result[i + 2] & 0x01) >> 0)
                if self._nStd_Ext == 1:
                    result_format.append(0)
                    valid_id = 0
                    for i in range(10):
                        result_format[0] = result_format[0] + (received_frame[i] << (28 - i))
                    for i in range(13, 30):
                        result_format[0] = result_format[0] + (received_frame[i] << (28 - i + 2))
                    if result_format[0] == self._id:
                        valid_id = 1
                    result_format[1] = self._nStd_Ext
                    result_format[2] = self._nData_Request
                    result_format[3] = (received_frame[34] << 3) + (received_frame[35] << 2) + (
                                received_frame[36] << 1) + (received_frame[37] << 0)  # Nb's bytes of Data
                    for i in range(result_format[3] - 1):
                        result_format[i + 4] = 0
                        for j in range(0, 7):
                            result_format[i + 4] = result_format[i + 4] + (
                                        received_frame[38 + j + (i * 8)] << (7 - j))  # Décalage de 1 à revoir !!
                    result_format[result_format[3] + 4] = 0
                    for i in range(14):
                        result_format[result_format[3] + 4] = result_format[result_format[3] + 4] + (
                                    received_frame[38 + (result_format[3] * 8) + i] << (14 - i))
                    valid_crc = self.crc_check(complete_frame=received_frame)
                else:
                    for i in range(10):
                        result_format[0] = result_format[0] + (received_frame[i] << (28 - i))
                    if result_format[0] == self._id:
                        valid_id = 1
                    result_format[1] = self._nStd_Ext
                    result_format[2] = self._nData_Request
                    result_format[3] = (received_frame[14] << 3) + (received_frame[15] << 2) + (
                                received_frame[16] << 1) + (received_frame[17] << 0)  # Nb's bytes of Data
                    for i in range(result_format[3] - 1):
                        result_format[i + 4] = 0
                        for j in range(7):
                            result_format[i + 4] = result_format[i + 4] + (received_frame[18 + j + (i * 8)] << 3)
                    result_format[result_format[3] + 4] = 0
                    for i in range(14):
                        result_format[result_format[3] + 4] = result_format[result_format[3] + 4] + received_frame[
                            18 + (result_format[3] * 8) + i]
                    valid_crc = self.crc_check(complete_frame=received_frame)
                if valid_id == 0:
                    result_format.insert(0, 0xaa)
                elif valid_crc == 0:
                    result_format.insert(0, 0xbb)
                else:
                    result_format.insert(0, 0x55)
                return result_format
        elif result[0] == 0xff:
            result_format.append(0xff)
            return result_format
        else:
            result_format.append(0x00)
            return result_format

    def interact(self):
        # Use parameters to create a tab with one bit as a part of the tab - arranged as the frame order
        # Also calculate the size of the frame
        complete_frame, size_frame = self.data_formating(id=self._id, n_std_ext=self._nStd_Ext, cmde=self._cmde,
                                                         n_data_request=self._nData_Request, data=self._data)
        # Calculate and add the crc at the end of the frame (same as before : 1bit = 1box of the tab)
        # Calculate new frame size
        complete_frame, size_frame = self.crc_calculation(complete_frame=complete_frame, crc_type=self._crc_type,
                                                          crc_poly=self._crc_poly, size_frame=size_frame)
        # Add stuff bits inside the frame (insert new elements in the tab)
        # Calculate new frame size
        complete_frame, size_bits = self.add_stuff_bytes(frame=complete_frame, size_frame=size_frame)
        # Prepare frame before sending to the FPGA - bytes formation
        # Calculate number of bytes witch are sent
        frame_bytes, size_bytes = self.prepare_frame(frame=complete_frame, size_frame_bits=size_bits)
        result = None
        result_format = None
        packet = self._api.prepare_packet()
        packet.append(0x00)
        packet.append((self._baud_rate & 0x00ff))  # Speed
        packet.append(((self._baud_rate & 0xff00) >> 8))  # Speed
        packet.append(size_bits & 0xff)  # Number of bits in the frame
        packet.append(((self._nData_Request & 0x01) << 7) + ((self._nStd_Ext & 0x01) << 6) + (
                    size_bytes & 0x0f))  # [nData_Request|nStd_Ext|0|0|syze bytes|syze bytes|syze bytes|syze bytes]
        while size_bytes > 0:
            packet.append(frame_bytes[size_bytes - 1] & 0xff)  # Frame in bytes
            size_bytes = size_bytes - 1
        try:
            result = self._api.send_and_receive_data(packet, 1000)[4:]
            if self._nData_Request == 1:
                # Formatting data :

                # result_format = [nERROR | ID | nStd_Ext | nData_Request |
                # Nb bytes Data | Data byte 1 | ... | Data byte n | CRC]

                # nERROR => 0xFF : no response from slave
                #    		 => 0xAA : bad ID received
                #        => 0xBB : bad CRC
                #        => 0x55 : NO ERROR
                result_format = self.formating_table(result=result)
        except HardsploitError.HardsploitNotFound:
            print("Hardsploit not found")
        except HardsploitError.USBError:
            print("USB ERRROR")

        if self._nData_Request == 0:
            return result  # write
        else:
            return result_format  # read

    def start_baud_rate_detection(self):
        packet = self._api.prepare_packet()
        packet.append(0x01)  # Command to start

        try:
            self._api.send_packet(packet)  # return number of data send
            print("Sent")
        except HardsploitError.HardsploitNotFound:
            print("Hardsploit not found")

    def end_baud_rate_detection(self):
        result = None
        packet = self._api.prepare_packet()
        packet.append(0x02)  # Command to stop

        try:
            result = self._api.send_and_receive_data(packet, 1000).drop(4)
        except HardsploitError.HardsploitNotFound:
            print("Hardsploit not found")
        except HardsploitError.USBError:
            print("USB ERRROR")

        if result != None:
            period_l = result[0] + (result[1] << 8) + (result[2] << 16) + (result[3] << 24)
            period_h = result[4] + (result[5] << 8) + (result[6] << 16) + (result[7] << 24)
            period = (period_h + period_l) / 2.00
            period = period * 6.66666666666 * (10 ** -9)  # seconds
            if period > 0:
                # standard frequencies
                freq = int(1 / period)
                if (freq > 1150000) and (freq <= 2000000):
                    return 1200000  # 1.2MHz
                elif (freq > 900000) and (freq <= 1150000):
                    return 1000000  # 1Mhz
                elif (freq > 650000) and (freq <= 900000):
                    return 800000  # 800kHz
                elif (freq > 325000) and (freq <= 650000):
                    return 500000  # 500kHz
                elif (freq > 190000) and (freq <= 325000):
                    return 250000  # 250kHz
                elif (freq > 100000) and (freq <= 190000):
                    return 125000  # 125kHz
                elif (freq > 50000) and (freq <= 100000):
                    return 62500  # 62.5kz
                elif (freq > 15000) and (freq <= 50000):
                    return 20000  # 20kHz
                elif (freq > 5000) and (freq <= 15000):
                    return 10000  # 10kHz
                else:
                    return 0
            else:
                return 0
        return 0

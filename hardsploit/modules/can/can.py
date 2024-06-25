import csv

import usb

from hardsploit.core import HardsploitError


class HardsploitCAN:

    def __init__(self, baud_rate, timeout, path, crc_poly, hardsploit_api):
        self._baud_rate = baud_rate
        self._timeout = timeout
        self._path = path
        self._crc_poly = crc_poly
        self._api = hardsploit_api
        self._payload = []

    @property
    def baud_rate(self):
        return 150000000 / self._baud_rate

    @baud_rate.setter
    def baud_rate(self, baud_rate):
        if (baud_rate >= 2400) and (baud_rate <= 2000000):
            self._baud_rate = 150000000 / baud_rate - 1
        else:
            raise HardsploitError.CANWrongSettings  # Change error settings

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, timeout):
        if (timeout >= 1) and (timeout <= 60):
            self._timeout = timeout * 1000
        else:
            raise HardsploitError.CANWrongSettings  # Change error settings

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, path):
        self._path = path

    @property
    def crc_poly(self):
        return self._crc_poly

    @crc_poly.setter
    def crc_poly(self, crc_poly):
        self._crc_poly = crc_poly

    def crc_calculation(self, complete_frame):
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

    def data_formating(self, result):
        complete_frame = []
        f = open(self._path, 'ab')
        writer = csv.writer(f)
        if result[0] == 85:  # SOF
            if result[1] == 0:  # No error
                for i in range(2, 14):
                    complete_frame.append((result[i] & 0x80) >> 7)
                    complete_frame.append((result[i] & 0x40) >> 6)
                    complete_frame.append((result[i] & 0x20) >> 5)
                    complete_frame.append((result[i] & 0x10) >> 4)
                    complete_frame.append((result[i] & 0x08) >> 3)
                    complete_frame.append((result[i] & 0x04) >> 2)
                    complete_frame.append((result[i] & 0x02) >> 1)
                    complete_frame.append((result[i] & 0x01) >> 0)
                complete_frame.append((result[15] & 0x80) >> 7)
                complete_frame.append((result[15] & 0x40) >> 6)
                complete_frame.append((result[15] & 0x20) >> 5)
                complete_frame.append((result[15] & 0x10) >> 4)
                complete_frame.append((result[15] & 0x08) >> 3)
                id = (result[2] << 3) + ((result[3] & 0xE0) >> 5)
                if (result[3] & 0x08) == 0x08:  # ID Exted
                    id_ext = (id << 18) + ((result[3] & 0x07) << 15) + (result[4] << 7) + (result[5] >> 1)
                    cmde = (result[6] & 0x3c) >> 2
                    if (result[5] & 0x01) == 0x01:  # request frame
                        crc = ((result[6] & 0x03) << 13) + (result[7] << 5) + ((result[8] & 0xf8) >> 3)
                        valid_crc = self.crc_calculation(complete_frame=complete_frame)
                        if valid_crc == 0:  # test erreur crc:#no error
                            writer.writerow([
                                f"Request; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}"
                                f"; - ; - ; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                        else:
                            writer.writerow([
                                f"Request; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}"
                                f"; - ; - ; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                    else:  # Data frame
                        if cmde == 1:
                            data_1 = ((result[6] & 0x03) << 6) + ((result[7] & 0xfc) >> 2)
                            crc = ((result[7] & 0x03) << 13) + (result[8] << 5) + ((result[9] & 0xf8) >> 3)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)}"
                                    f"; - ; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)}"
                                    f"; - ; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 2:
                            data_1 = ((result[6] & 0x03) << 6) + ((result[7] & 0xfc) >> 2)
                            data_2 = ((result[7] & 0x03) << 6) + ((result[8] & 0xfc) >> 2)
                            crc = ((result[8] & 0x03) << 13) + (result[9] << 5) + ((result[10] & 0xf8) >> 3)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 3:
                            data_1 = ((result[6] & 0x03) << 6) + ((result[7] & 0xfc) >> 2)
                            data_2 = ((result[7] & 0x03) << 6) + ((result[8] & 0xfc) >> 2)
                            data_3 = ((result[8] & 0x03) << 6) + ((result[9] & 0xfc) >> 2)
                            crc = ((result[9] & 0x03) << 13) + (result[10] << 5) + ((result[11] & 0xf8) >> 3)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}"
                                    f"; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}"
                                    f"; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 4:
                            data_1 = ((result[6] & 0x03) << 6) + ((result[7] & 0xfc) >> 2)
                            data_2 = ((result[7] & 0x03) << 6) + ((result[8] & 0xfc) >> 2)
                            data_3 = ((result[8] & 0x03) << 6) + ((result[9] & 0xfc) >> 2)
                            data_4 = ((result[9] & 0x03) << 6) + ((result[10] & 0xfc) >> 2)
                            crc = ((result[10] & 0x03) << 13) + (result[11] << 5) + ((result[12] & 0xf8) >> 3)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)}"
                                    f"; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)}"
                                    f"; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 5:
                            data_1 = ((result[6] & 0x03) << 6) + ((result[7] & 0xfc) >> 2)
                            data_2 = ((result[7] & 0x03) << 6) + ((result[8] & 0xfc) >> 2)
                            data_3 = ((result[8] & 0x03) << 6) + ((result[9] & 0xfc) >> 2)
                            data_4 = ((result[9] & 0x03) << 6) + ((result[10] & 0xfc) >> 2)
                            data_5 = ((result[10] & 0x03) << 6) + ((result[11] & 0xfc) >> 2)
                            crc = ((result[11] & 0x03) << 13) + (result[12] << 5) + ((result[13] & 0xf8) >> 3)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 6:
                            data_1 = ((result[6] & 0x03) << 6) + ((result[7] & 0xfc) >> 2)
                            data_2 = ((result[7] & 0x03) << 6) + ((result[8] & 0xfc) >> 2)
                            data_3 = ((result[8] & 0x03) << 6) + ((result[9] & 0xfc) >> 2)
                            data_4 = ((result[9] & 0x03) << 6) + ((result[10] & 0xfc) >> 2)
                            data_5 = ((result[10] & 0x03) << 6) + ((result[11] & 0xfc) >> 2)
                            data_6 = ((result[11] & 0x03) << 6) + ((result[12] & 0xfc) >> 2)
                            crc = ((result[12] & 0x03) << 13) + (result[13] << 5) + ((result[14] & 0xf8) >> 3)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)};"
                                    f" - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)};"
                                    f" - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 7:
                            data_1 = ((result[6] & 0x03) << 6) + ((result[7] & 0xfc) >> 2)
                            data_2 = ((result[7] & 0x03) << 6) + ((result[8] & 0xfc) >> 2)
                            data_3 = ((result[8] & 0x03) << 6) + ((result[9] & 0xfc) >> 2)
                            data_4 = ((result[9] & 0x03) << 6) + ((result[10] & 0xfc) >> 2)
                            data_5 = ((result[10] & 0x03) << 6) + ((result[11] & 0xfc) >> 2)
                            data_6 = ((result[11] & 0x03) << 6) + ((result[12] & 0xfc) >> 2)
                            data_7 = ((result[12] & 0x03) << 6) + ((result[13] & 0xfc) >> 2)
                            crc = ((result[13] & 0x03) << 13) + (result[14] << 5) + ((result[15] & 0xf8) >> 3)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; 0x{int(data_7, 16)};"
                                    f" - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; 0x{int(data_7, 16)};"
                                    f" - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 8:
                            data_1 = ((result[6] & 0x03) << 6) + ((result[7] & 0xfc) >> 2)
                            data_2 = ((result[7] & 0x03) << 6) + ((result[8] & 0xfc) >> 2)
                            data_3 = ((result[8] & 0x03) << 6) + ((result[9] & 0xfc) >> 2)
                            data_4 = ((result[9] & 0x03) << 6) + ((result[10] & 0xfc) >> 2)
                            data_5 = ((result[10] & 0x03) << 6) + ((result[11] & 0xfc) >> 2)
                            data_6 = ((result[11] & 0x03) << 6) + ((result[12] & 0xfc) >> 2)
                            data_7 = ((result[12] & 0x03) << 6) + ((result[13] & 0xfc) >> 2)
                            data_8 = ((result[13] & 0x03) << 6) + ((result[14] & 0xfc) >> 2)
                            crc = ((result[14] & 0x03) << 13) + (result[15] << 5) + ((result[16] & 0xf8) >> 3)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; 0x{int(data_7, 16)};"
                                    f" 0x{int(data_8, 16)}; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Exted; 0x{int(id_ext, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; 0x{int(data_7, 16)};"
                                    f" 0x{int(data_8, 16)}; 0x{int(crc, 16)}; CRC ERROR"])
                else:  # Standard ID
                    cmde = ((result[3] & 0x03) << 2) + ((result[4] & 0xc0) >> 6)
                    if (result[3] & 0x10) == 0x10:  # Request frame
                        crc = ((result[4] & 0x3f) << 9) + (result[5] << 1) + ((result[6] & 0x80) >> 7)
                        valid_crc = self.crc_calculation(complete_frame=complete_frame)
                        if valid_crc == 0:  # test erreur crc #no error
                            writer.writerow([
                                f"Request; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}"
                                f"; - ; - ; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                        else:
                            writer.writerow([
                                f"Request; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}"
                                f"; - ; - ; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                    else:  # Data frame
                        if cmde == 1:
                            data_1 = ((result[4] & 0x3f) << 2) + ((result[5] & 0xc0) >> 6)
                            crc = ((result[5] & 0x3f) << 9) + (result[6] << 1) + ((result[7] & 0x80) >> 7)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)}"
                                    f"; - ; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)}"
                                    f"; - ; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 2:
                            data_1 = ((result[4] & 0x3f) << 2) + ((result[5] & 0xc0) >> 6)
                            data_2 = ((result[5] & 0x3f) << 2) + ((result[6] & 0xc0) >> 6)
                            crc = ((result[6] & 0x3f) << 9) + (result[7] << 1) + ((result[8] & 0x80) >> 7)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; - ; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 3:
                            data_1 = ((result[4] & 0x3f) << 2) + ((result[5] & 0xc0) >> 6)
                            data_2 = ((result[5] & 0x3f) << 2) + ((result[6] & 0xc0) >> 6)
                            data_3 = ((result[6] & 0x3f) << 2) + ((result[7] & 0xc0) >> 6)
                            crc = ((result[7] & 0x3f) << 9) + (result[8] << 1) + ((result[9] & 0x80) >> 7)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}"
                                    f"; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}"
                                    f"; - ; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 4:
                            data_1 = ((result[4] & 0x3f) << 2) + ((result[5] & 0xc0) >> 6)
                            data_2 = ((result[5] & 0x3f) << 2) + ((result[6] & 0xc0) >> 6)
                            data_3 = ((result[6] & 0x3f) << 2) + ((result[7] & 0xc0) >> 6)
                            data_4 = ((result[7] & 0x3f) << 2) + ((result[8] & 0xc0) >> 6)
                            crc = ((result[8] & 0x3f) << 9) + (result[9] << 1) + ((result[10] & 0x80) >> 7)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)}"
                                    f"; - ; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)}"
                                    f"; - ; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 5:
                            data_1 = ((result[4] & 0x3f) << 2) + ((result[5] & 0xc0) >> 6)
                            data_2 = ((result[5] & 0x3f) << 2) + ((result[6] & 0xc0) >> 6)
                            data_3 = ((result[6] & 0x3f) << 2) + ((result[7] & 0xc0) >> 6)
                            data_4 = ((result[7] & 0x3f) << 2) + ((result[8] & 0xc0) >> 6)
                            data_5 = ((result[8] & 0x3f) << 2) + ((result[9] & 0xc0) >> 6)
                            crc = ((result[9] & 0x3f) << 9) + (result[10] << 1) + ((result[11] & 0x80) >> 7)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; - ; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; - ; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 6:
                            data_1 = ((result[4] & 0x3f) << 2) + ((result[5] & 0xc0) >> 6)
                            data_2 = ((result[5] & 0x3f) << 2) + ((result[6] & 0xc0) >> 6)
                            data_3 = ((result[6] & 0x3f) << 2) + ((result[7] & 0xc0) >> 6)
                            data_4 = ((result[7] & 0x3f) << 2) + ((result[8] & 0xc0) >> 6)
                            data_5 = ((result[8] & 0x3f) << 2) + ((result[9] & 0xc0) >> 6)
                            data_6 = ((result[9] & 0x3f) << 2) + ((result[10] & 0xc0) >> 6)
                            crc = ((result[10] & 0x3f) << 9) + (result[11] << 1) + ((result[12] & 0x80) >> 7)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; - ; - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)};"
                                    f" 0x{int(data_4, 16)}; 0x{int(data_5, 16)};"
                                    f" 0x{int(data_6, 16)}; - ; - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 7:
                            data_1 = ((result[4] & 0x3f) << 2) + ((result[5] & 0xc0) >> 6)
                            data_2 = ((result[5] & 0x3f) << 2) + ((result[6] & 0xc0) >> 6)
                            data_3 = ((result[6] & 0x3f) << 2) + ((result[7] & 0xc0) >> 6)
                            data_4 = ((result[7] & 0x3f) << 2) + ((result[8] & 0xc0) >> 6)
                            data_5 = ((result[8] & 0x3f) << 2) + ((result[9] & 0xc0) >> 6)
                            data_6 = ((result[9] & 0x3f) << 2) + ((result[10] & 0xc0) >> 6)
                            data_7 = ((result[10] & 0x3f) << 2) + ((result[11] & 0xc0) >> 6)
                            crc = ((result[11] & 0x3f) << 9) + (result[12] << 1) + ((result[13] & 0x80) >> 7)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; 0x{int(data_7, 16)};"
                                    f" - ; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; 0x{int(data_7, 16)};"
                                    f" - ; 0x{int(crc, 16)}; CRC ERROR"])
                        elif cmde == 8:
                            data_1 = ((result[4] & 0x3f) << 2) + ((result[5] & 0xc0) >> 6)
                            data_2 = ((result[5] & 0x3f) << 2) + ((result[6] & 0xc0) >> 6)
                            data_3 = ((result[6] & 0x3f) << 2) + ((result[7] & 0xc0) >> 6)
                            data_4 = ((result[7] & 0x3f) << 2) + ((result[8] & 0xc0) >> 6)
                            data_5 = ((result[8] & 0x3f) << 2) + ((result[9] & 0xc0) >> 6)
                            data_6 = ((result[9] & 0x3f) << 2) + ((result[10] & 0xc0) >> 6)
                            data_7 = ((result[10] & 0x3f) << 2) + ((result[11] & 0xc0) >> 6)
                            data_8 = ((result[11] & 0x3f) << 2) + ((result[12] & 0xc0) >> 6)
                            crc = ((result[12] & 0x3f) << 9) + (result[13] << 1) + ((result[14] & 0x80) >> 7)
                            valid_crc = self.crc_calculation(complete_frame=complete_frame)
                            if valid_crc == 0:  # test erreur crc #no error
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; 0x{int(data_7, 16)};"
                                    f" 0x{int(data_8, 16)}; 0x{int(crc, 16)}; NO ERROR"])
                            else:
                                writer.writerow([
                                    f"Data; Standard; 0x{int(id, 16)}; 0x{int(cmde, 16)}; 0x{int(data_1, 16)};"
                                    f" 0x{int(data_2, 16)}; 0x{int(data_3, 16)}; 0x{int(data_4, 16)};"
                                    f" 0x{int(data_5, 16)}; 0x{int(data_6, 16)}; 0x{int(data_7, 16)};"
                                    f" 0x{int(data_8, 16)}; 0x{int(crc, 16)}; CRC ERROR"])
            else:
                writer.writerow([" - ; - ; - ; - ; - ; - ; - ; - ; - ; - ; - ; - ; - ; FRAME ERROR"])
        else:
            writer.writerow([" - ; - ; - ; - ; - ; - ; - ; - ; - ; - ; - ; - ; - ; SNIFFER ERROR"])

    def sniffer(self):  # Path : csv file
        packet = self._api.prepare_packet()
        packet.append(0x00)  # Sniffer command
        packet.append((self._baud_rate & 0x00ff))
        packet.append(((self._baud_rate & 0xff00) >> 8))
        packet.append((self._crc_poly & 0x00ff))
        packet.append(((self._crc_poly & 0xff00) >> 8))
        self._api.sPacket(packet)
        f = open(self._path, 'wb')
        writer = csv.writer(f)
        writer.writerow([
            "Request/Data; Exted/Standard; ID; Commande;"
            " Data 1; Data 2; Data 3; Data 4; Data 5; Data 6; Data 7; Data 8; CRC; ERROR"])
        stop = False
        result = []
        while not stop:
            try:
                result = self._api.receive_data(self._timeout)[4:]  # 10s timeout
                self.data_formating(result=result)
            except usb.core.USBTimeoutError:
                stop = True
        # result = HardsploitAPI.instance.sAndReceiveDATA(packet,10000).drop(4) #Timeout 10s
        # Ajouter boucle pour recevoir toutes les trames jusqu'à stop du sniffer
        # clean_file_csv(result: result, path: @path)
        # CSV.close()
        return result

from time import sleep

from hardsploit.core import HardsploitUtils


class SwdDebugPort:

    def __init__(self, swd_api):
        self.swd = swd_api
        sleep(0.5)
        self.swd.reset_swd()

        self.cur_ap = -1
        self.cur_bank = -1
        self.abort(1, 1, 1, 1, 1)
        self.select(0, 0)

        # power shit up
        HardsploitUtils.console_info("Power shit up")

        self.swd.write_swd(False, 1, 0x54000000)
        if (self.status() >> 24) != 0xF4:
            raise "error powering up system"
        HardsploitUtils.console_info("POWERING UP SYTEM OK")

    def get_api(self):
        return self.swd

    def idcode(self):
        return self.swd.read_swd(False, 0)

    def abort(self, orunerr, wdataerr, stickyerr, stickycmp, dap):
        value = 0x00000000
        value |= (0x10 if orunerr else 0x00)
        value |= (0x08 if wdataerr else 0x00)
        value |= (0x04 if stickyerr else 0x00)
        value |= (0x02 if stickycmp else 0x00)
        value |= (0x01 if dap else 0x00)
        self.swd.write_swd(False, 0, value)

    def status(self):
        val = self.swd.read_swd(False, 1)
        return val

    def control(self, trn_count=0, trn_mode=0, mask_lane=0, orun_detect=0):
        value = 0x54000000
        value = value | ((trn_count & 0xFFF) << 12)
        value = value | ((mask_lane & 0x00F) << 8)
        value = value | ((trn_mode & 0x003) << 2)
        value |= (0x01 if orun_detect else 0x00)
        self.swd.write_swd(False, 1, value)

    def select(self, apsel, apbank):
        if apsel != self.cur_ap or apbank != self.cur_bank:
            self.cur_ap = apsel
            self.cur_bank = apbank
            value = 0 | ((apsel & 0xFF) << 24) | ((apbank & 0x0F) << 4)
            self.swd.write_swd(False, 2, value)

    def read_rb(self):
        return self.swd.read_swd(False, 3)

    def read_ap(self, apsel, address):
        adr_bank = (address >> 4) & 0xF
        adr_reg = (address >> 2) & 0x3
        self.select(apsel, adr_bank)
        return self.swd.read_swd(True, adr_reg)

    def write_ap(self, apsel, address, data):
        adr_bank = (address >> 4) & 0xF
        adr_reg = (address >> 2) & 0x3
        self.select(apsel, adr_bank)
        self.swd.write_swd(True, adr_reg, data)

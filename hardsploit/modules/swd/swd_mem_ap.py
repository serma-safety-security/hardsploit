class SwdMemAp:

    def __init__(self, dp, apsel):
        self.dp = dp
        self.apsel = apsel
        self.csw(1, 2)  # 32-bit auto-incrementing addressing

    def csw(self, addr_inc, size):
        self.dp.read_ap(self.apsel, 0x00)
        val = self.dp.read_rb() & 0xFFFFFF00
        self.dp.write_ap(self.apsel, 0x00, val + (addr_inc << 4) + size)

    def idcode(self):
        self.dp.read_ap(self.apsel, 0xFC)
        id = self.dp.read_rb()
        self.dp.select(0, 0)
        return id

    def read_word(self, addr):
        self.dp.write_ap(self.apsel, 0x04, addr)
        self.dp.read_ap(self.apsel, 0x0C)
        return self.dp.read_rb()

    def write_word(self, addr, data):
        self.dp.write_ap(self.apsel, 0x04, addr)
        self.dp.write_ap(self.apsel, 0x0C, data)
        return self.dp.read_rb()

    def read_block(self, address, size):
        # 1K boundaries and return 4K of data word alignement
        if size < 1:
            raise "readBlock error : count must be >= 1"
        if size > 1024:
            raise "readBlock error : size must be <= 1024 "
        return self.dp.get_api().read_mem32(address, size)

    def write_block(self, address, data):
        # 1K boundaries
        if len(data) < 1:
            raise "readBlock error : count must be >= 1"
        if len(data) > 1024:
            raise "readBlock error : size must be <= 1024 "
        self.dp.get_api().write_mem16_packed(address, data)

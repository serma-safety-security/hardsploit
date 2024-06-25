import time
import usb.core
import usb.util

from hardsploit.core import HardsploitConstant, HardsploitUtils, HardsploitError


class HardsploitUSBCommunication:

    connected_devices = []

    def __init__(self):
        self.dev = None
        self.devices = None
        self.dfu = False
        self.connect()

    # Connect board and get an instance to work with
    # Return USB_STATE
    def connect(self):
        # self.usb = LIBUSB::Context.new
        self.devices = list(usb.core.find(idVendor=0x0483, idProduct=0xFFFF, find_all=True))
        if len(self.devices) == 0:
            self.dev = None
            self.devices = list(usb.core.find(idVendor=0x0483, idProduct=0xDF11, find_all=True))
            if len(self.devices) == 0:
                raise HardsploitError.HardsploitNotFound
            else:
                print("!!! DFU STATE : only loadFirmware('uC') available !!!!")
                self.dfu = True
        else:
            if len(self.devices) <= 0:
                raise HardsploitError.HardsploitNotFound
            else:
                try:
                    if self.dev is None:
                        for device in self.devices:
                            if device.address not in HardsploitUSBCommunication.connected_devices:
                                self.dev = device
                                HardsploitUSBCommunication.connected_devices.append(device.address)
                                break
                    self.start_fpga()
                    time.sleep(0.1)
                    self.set_status_led(HardsploitConstant.UsbCommand.GREEN_LED, state=True)
                except:
                    raise HardsploitError.USBError

    def reconnect(self):
        # @usb = LIBUSB::Context.new
        self.devices = usb.core.find(idVendor=0x0483, idProduct=0xFFFF, find_all=True)
        if len(list(self.devices)) == 0:
            self.dev = None
            raise HardsploitError.HardsploitNotFound
        else:
            if len(list(self.devices)) <= 0:
                raise HardsploitError.HardsploitNotFound
            else:
                try:
                    if self.dev is None:
                        self.dev = self.devices[0]
                    self.start_fpga()
                    time.sleep(0.1)
                    self.set_status_led(HardsploitConstant.UsbCommand.GREEN_LED, state=True)
                except:
                    raise HardsploitError.USBError

    # Send data and wait to receive response
    # * +packet_send+:: array of byte
    # * +timeout+:: timeout to read response (ms)
    # Return USB_STATE or array with response (improve soon with exception)
    def send_and_receive_data(self, packet_send, timeout):
        try:
            self.send_packet(packet_send)
            received_data = self.dev.read(endpoint=HardsploitConstant.USB.IN_ENDPOINT,
                                          size_or_buffer=HardsploitConstant.USB.USB_TRAME_SIZE, timeout=timeout)
            print("data received: " + str(received_data))
            # HardsploitAPI.HardsploitAPI.consoleSpeed(
            #   "RECEIVE {}Bytes/s  {}Bytes in  {} s".format(round(received_data/EndTime, 2),
            #                                                 received_data, round(EndTime, 4)))
            return received_data
        except usb.core.USBError:
            raise HardsploitError.USBError
        except:
            raise HardsploitError.HardsploitNotFound

    # Wait to receive data
    # * +timeout+:: timeout to read response (ms)
    # Return USB_STATE or array with response (improve soon with exception)
    def receive_data(self, timeout):
        try:
            received_data = self.dev.read(endpoint=HardsploitConstant.USB.IN_ENDPOINT,
                                          size_or_buffer=HardsploitConstant.USB.USB_TRAME_SIZE, timeout=timeout)
            return str.encode(received_data)
        except usb.core.USBError:
            raise HardsploitError.USBError
        except:
            raise HardsploitError.HardsploitNotFound

    # Send USB packet
    # * +packet+:: array with bytes
    # Return number of byte sent
    def send_packet(self, packet_send):
        try:
            if len(packet_send) <= 8191:
                packet_send[0] = HardsploitUtils.low_byte(len(packet_send))
                packet_send[1] = HardsploitUtils.high_byte(len(packet_send))

                # if a multiple of packet size add a value to explicit the end of trame
                if len(packet_send) % 64 == 0:
                    packet_send.append(0)

                # print(f"Send: {packet_send}")
                start_time = time.time()
                number_of_data_send = self.dev.write(endpoint=HardsploitConstant.USB.OUT_ENDPOINT,
                                                     data=bytearray(packet_send), timeout=3000)
                end_time = time.time() - start_time
                HardsploitUtils.console_speed(
                    "RECEIVE {}Bytes/s  {}Bytes in  {} s".format(round((float(number_of_data_send) / end_time), 2),
                                                                 number_of_data_send, round(end_time, 4)))
                if number_of_data_send == len(packet_send):
                    return number_of_data_send
                else:
                    raise HardsploitError.USBError
            else:
                raise HardsploitError.USBError
        except usb.core.USBError:
            raise HardsploitError.USBError
        except:
            # TRY TO RECONNECT maybe error due to disconnecting and reconnecting board
            HardsploitUSBCommunication.connected_devices.remove(self.dev.address)
            self.reconnect()

    def start_fpga(self):
        packet = [HardsploitUtils.low_byte(word=4),
                  HardsploitUtils.high_byte(word=4),
                  HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.START_FPGA),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.START_FPGA)]
        self.send_packet(packet)

    def stop_fpga(self):
        packet = [HardsploitUtils.low_byte(word=4),
                  HardsploitUtils.high_byte(word=4),
                  HardsploitUtils.low_byte(word=HardsploitConstant.UsbCommand.STOP_FPGA),
                  HardsploitUtils.high_byte(word=HardsploitConstant.UsbCommand.STOP_FPGA)]
        self.send_packet(packet)

    # Set the leds of uC  returning nothing
    # * +led+:: USB_COMMAND::GREEN_LED  or USB_COMMAND::RED_LED
    # * +state+:: callback to return +data for dump function+
    def set_status_led(self, led, state):
        packet_send = [0, 0, HardsploitUtils.low_byte(word=led), HardsploitUtils.high_byte(word=led), (1 if state else 0)]
        return self.send_packet(packet_send)

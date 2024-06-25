import time

import usb.core


class HardsploitI2cSniffer:

    def __init__(self, timeout, hardsploit_api):
        self._timeout = timeout
        self._api = hardsploit_api

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, timeout):
        self._timeout = timeout

    def i2c_start_sniff(self, path):
        packet = self._api.prepare_packet()
        packet.append(0x55)
        self._api.send_packet(packet)
        result = ""
        file = open(path, "wb")
        stop = False
        while not stop:
            try:
                result = list(self._api.receive_data(self.timeout))[4:]
                print(result)
                file.write(bytes(result))

            except usb.core.USBTimeoutError:
                end_packet = self._api.prepare_packet()
                end_packet.append(0xaa)
                try:
                    result = list(self._api.send_and_receive_data(end_packet, 1000))[4:]
                    print(result)
                    file.write(bytes(result))
                    file.close()

                except Exception:
                    pass

                stop = True
            time.sleep(0.01)

        print(len(result))
        return result

    def i2c_stop_sniff(self):
        end_packet = self._api.prepare_packet()
        end_packet.append(0xaa)
        result = ""
        try:
            result = list(self._api.send_and_receive_data(end_packet, 1000))[4:]
            print(result)
            print(len(result))
        except Exception:
            pass

        return result

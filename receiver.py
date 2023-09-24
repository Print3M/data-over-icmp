#!/usr/bin/python3
#
# GitHub: Print3M
#
# Feel free to do whatever you want with this script.
# Example usage is included in the main function at the bottom of the file.
#
import socket
import zlib
import sys
import struct


class ReceiverICMP:
    def __init__(self, port):
        self.port = port
        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        self.socket.bind(("", port))
        self.data = None

    def listen(self):
        """
        Listen for ONE SEQUENCE of packets. It means that
        it could be more than one packet but they have to be in one sequence.
        Listener know about the end of the sequence because of timeout.
        Then data is extracted from received packets.
        """
        packets_list = []

        while True:
            try:
                packet = self.socket.recv(65535)
            except socket.timeout:
                break
            finally:
                # After first received packet set timeout for incoming
                self.socket.settimeout(0.5)

            # Extract icmp from ip
            icmp = self._remove_ip_headers(packet)

            # Recognize request (not replay), collect data and sequence number
            if icmp[0] == 0x08:
                packets_list.append(
                    {
                        "seq": struct.unpack("!H", icmp[6:8])[0],
                        "data": self._get_icmp_data(icmp),
                    }
                )

        # Reset timeout
        self.socket.settimeout(None)
        self.data = self._prepare_data(packets_list)

    def _prepare_data(self, packets_list):
        """
        :packets_list - list of dicts e.g. {data: b'example', seq: 54}
            1. Sort list by sequence number in dicts.
            2. Join bytes-like data of all dicts.
            3. Decompress data
            4. Decode data
        """
        sorted_packets_list = sorted(packets_list, key=lambda k: k["seq"])
        compressed_data = b"".join([packet["data"] for packet in sorted_packets_list])
        clean_data = zlib.decompress(compressed_data).decode()

        return clean_data

    def _remove_ip_headers(self, bytes_packet):
        return bytes_packet[20:]

    def _get_icmp_data(self, bytes_packet):
        return bytes_packet[8:]


#############################
#                           #
#       EXAMPLE USAGE       #
#                           #
#############################

if __name__ == "__main__":
    receiver = ReceiverICMP(port=50)

    while True:
        # Receive data
        receiver.listen()
        # Print received data
        print(f">>> {receiver.data}")

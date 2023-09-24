# Send data over ICMP

> **IMPORTANT**: This script has been written years ago, before Python type-checking become popular. It's highly unmaintained and propably doesn't work well anymore. After all it gives a nice view of ICMP communication.

Useless (or not ( ͡° ͜ʖ ͡°)) class for sending and receiving data over ICMP. Hobby project to just learn more about ICMP structure and socket API.

Examples of usage are included in the `receiver.py` and`sender.py` files.

## sender.py
Class for sending data over ICMP packets (with implemented automatic data segmentation and compression) within a *data* field.

## reciver.py
Class for receiving data sent over ICMP packets (with desegmentation and decompression).

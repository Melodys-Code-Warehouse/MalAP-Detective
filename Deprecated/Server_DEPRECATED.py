import socket
from socket import *
from Server import *
import geoip2.database
import urllib.request
import json
import struct
import binascii
import ssl

DEFAULT_PORT = 4433


# other code remains the same...

def start_server(port=DEFAULT_PORT):
    # socket
    sock = socket(AF_INET, SOCK_STREAM)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  # Disable old TLS versions
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")  # Load server certificate and key

    sock = context.wrap_socket(sock, server_side=True)

    # binding addr and port
    server_address = ('', port)
    sock.bind(server_address)

    # start
    sock.listen(1)
    print(f"VeriDNS server listening on port {port}...")

    # wait for cli
    while True:
        client_socket, client_address = sock.accept()
        print(f"Got TLS 1.3 connection from {client_address}")

        # handle client connection over SSL/TLS
        handle_client(client_socket, client_address, client_socket)

        # close conn
        client_socket.close()


if __name__ == '__main__':
    start_server()
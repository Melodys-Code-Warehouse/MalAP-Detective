import socket
import geoip2.database
import urllib.request
import json
import struct
import binascii
import ssl

DEFAULT_PORT = 4433

# 请求类型常量值
BRANCH_SERVER_ADDRESS_QUERY = 0
BRANCH_SERVER_ADDRESS_ANSWER = 1
VERIDNS_REQUEST = 2
VERIDNS_RESPONSE = 3

# BRANCH_SERVER_TABLE: tuple('Country_name',ip.addr)
BRANCH_SERVER_TABLE = [
    ['Hong Kong', '20.239.49.221'],
    ['China', '47.120.36.211'],
    # TODO Complete the IP address of student server in Singapore
    ['Singapore', '192.168.0.1']
]


def lookup_branch_ip(branch_name):
    for branch in BRANCH_SERVER_TABLE:
        if branch[0] == branch_name:
            return branch[1]
    return '20.239.49.221'


def handle_client(sock, client_address, client_port):
    # 接收客户端的数据包
    data = b''
    while True:
        recv_data = sock.recv(10240)
        if not recv_data:
            break
        data += recv_data
    # print(data)
    # str_data = data.decode('utf-8')
    # str_data = str_data.replace('\\x', '')
    # data = str_data.encode('utf-8')
    print(len(data))
    hex_Type = data[:4]
    hex_Length = data[4:8]
    hex_SequenceNumber = data[8:12]

    dec_Type = int.from_bytes(data[:4], byteorder='little', signed=False)
    dec_Length = int.from_bytes(data[4:8], byteorder='little', signed=False)
    dec_SequenceNumber = int.from_bytes(data[8:12], byteorder='big', signed=False)
    print(data[:4])
    print(data[4:8])
    print(data[8:12])
    print(dec_Type)
    print(hex_SequenceNumber)
    print(dec_SequenceNumber)
    print(data)
    if dec_Type == 0:
        # IP Address Query Module
        # TODO:修改为正确数据库路径
        reader = geoip2.database.Reader('/home/noir/GeoLite2-City.mmdb')
        ret = reader.city(client_address[0])
        cli_ip_country = ret.country.name

        # Response Field
        Response = b''
        Re_Type = b'\x00\x00\x00\x01'
        Re_SeqNum = hex_SequenceNumber
        Re_NUmberOfAddr = b'\x00\x00\x00\x01'
        Re_BranchIPAddr = socket.inet_aton(lookup_branch_ip(cli_ip_country))
        print(Re_BranchIPAddr)
        Re_Length = b'\x00\x00\x00\x14'

        Response = Re_Type + Re_Length + Re_SeqNum + Re_NUmberOfAddr \
                   + Re_BranchIPAddr

        # TODO: 删除测试函数
        print(cli_ip_country)
        print(len(Response))
        print(Response)

        # Socket Field
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        ######################################################################
        #                TODO:2023-07-23 04:02AM DEBUG-STATE                 #
        # server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#
        ######################################################################

        client_socket_adderss = client_address
        server_socket.connect(client_socket_adderss)

        server_socket.send(Response)
        server_socket.close()

    elif dec_Type == 2:
        hex_DomainName = data[12:12+256]
        hex_NumberOfAddr = data[12+256:12+256+4]

        # TODO:注释掉下面的输出测试
        print("hex_NumberOfAddr=" + str(hex_NumberOfAddr))
        dec_NumberOfAddr = int(hex_NumberOfAddr.decode('ascii'), 16)

        # TODO:注释掉下面的输出测试
        print("dec_NumberOfAddr=" + str(dec_NumberOfAddr))
        hex_IPAddress = data[544:544 + dec_NumberOfAddr * 8]
        print("hex_IPAddress=" + str(hex_IPAddress))
        # ############################# BUG below #######################################
        # hex_DomainName_list = hex_DomainName.split()
        # hex_DomainName_array = bytearray([int(b, 16) for b in hex_DomainName_list])
        # str_DomainName = hex_DomainName_array.decode('utf-8')
        #################################################################################

        str_DomainName = hex_DomainName.decode("utf-8")
        # Resolution of None zero chr
        print("str_DomainName="+str_DomainName)
        domain_parts = []
        label = ''
        for i in range(0, len(str_DomainName), 2):
            if str_DomainName[i:i + 2] == '00':
                if label:
                    domain_parts.append(label)
                    label = ''
            else:
                label += chr(int(str_DomainName[i:i + 2], 16))
        DomainName = '.'.join(domain_parts).rstrip('\n')

        # TODO:删除测试函数
        print("DomainName=" + DomainName)
        for i in range(dec_NumberOfAddr):
            print("ipstring = " + socket.inet_ntoa(bytes.fromhex(hex_IPAddress[i:i + 8].decode('utf-8'))))

        list_IPAddress = [socket.inet_ntoa(bytes.fromhex(hex_IPAddress[i:i + 8].decode('utf-8'))) for i in range(dec_NumberOfAddr)]

        print("list_IPAddress=" + str(list_IPAddress))
        # Google DNS Request API
        name = "name=" + DomainName
        url = "https://dns.google/resolve?" + name + "&type=1"

        response = urllib.request.urlopen(url)
        ret_DNS_json = response.read().decode('utf-8')

        # JSON Resolution
        json_str = ret_DNS_json
        data = json.loads(json_str)
        authed_list_IPAddress = [answer['data'] for answer in data['Answer'] if answer['type'] == 1]
        print("authed_list_IPAddress=" + str(authed_list_IPAddress))
        # MaliciousIP Discovery
        list_MaliciousIP = [ip for ip in list_IPAddress if ip not in authed_list_IPAddress]
        # TODO:TEST
        print("list_MalIPAddress=" + str(list_MaliciousIP))

        # Verification
        Verification = b'01' if len(list_MaliciousIP) == 0 else b'00'
        # TODO:TEST
        print("Verification= " + str(Verification))

        # MaliciousIP to hex byte stream
        hex_byte_list_MaliciousIP = b''
        for ip in list_MaliciousIP:
            hex_byte_list_MaliciousIP += binascii.unhexlify(''.join(['{:02x}'.format(int(x)) for x in ip.split('.')]))

        # Response Construction
        Re_Type = b'00000004'
        Re_SeqNum = hex_SequenceNumber
        Re_Verification = Verification
        Re_NumberOfAddr = struct.pack('I', len(list_MaliciousIP))[::-1]
        Re_MaliciousIP = hex_byte_list_MaliciousIP
        Re_Length = len(Re_Type + Re_SeqNum + Re_Verification + Re_NumberOfAddr + Re_MaliciousIP)
        # TODO:TEST
        print("Re_Length=" + str(Re_Length))

        Response = Re_Type + struct.pack('>I',
                                         Re_Length) + Re_SeqNum + Re_Verification + Re_NumberOfAddr + Re_MaliciousIP

        print("Response="+str(Response))

        # Socket Field
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket_adderss = client_address
        server_socket.connect(client_socket_adderss)

        server_socket.send(Response)
        server_socket.close()
    else:
        pass
    # =======================Following part for test only===========================
    # print(dec_Type)
    # print(dec_Length)
    # print(dec_SequenceNumber)


def start_server(port=DEFAULT_PORT):
    # socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # binding addr and port
    # 20.239.49.221
    # sock.settimeout(0)

    server_address = ('', port)
    sock.bind(server_address)

    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #
    # context.load_cert_chain('server_cert.crt', 'server_key.key')

    # start
    sock.listen(100)
    print(f"VeriDNS server listening on port {port}...")

    # wait for cli
    while True:
        client_socket, client_address = sock.accept()

        # ssl_sock = context.wrap_socket(client_socket, server_side=True)

        print(f"Got connection from {client_address}")

        # =======================Following part for test only===========================
        # reader = geoip2.database.Reader('/home/DOTAGroup8/GeoLite2-City.mmdb')
        # ret = reader.city(client_address[0])
        # cli_ip_country = ret.country.name
        # print(cli_ip_country)
        # print(get_country_by_ip(client_address))
        # print(client_address)
        # print(type(client_address[0]))
        # print(get_country_by_ip(client_address[0]))
        # ==============================================================================

        # handle affairs
        handle_client(client_socket, client_address, client_socket)

        # close conn
        client_socket.close()


if __name__ == '__main__':
    start_server()

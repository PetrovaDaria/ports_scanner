import threading
import json
import socket
import struct
import datetime


MESSAGE = 192 * b'Q'
BUFFER_SIZE = 1024


class ScanManager:
    def __init__(self, host, left_boundary_port, right_boundary_port, need_tcp_scan,
                 need_udp_scan, need_protocols_scan, threads_count):
        self.host = host
        self.left_boundary_port = left_boundary_port
        self.right_boundary_port = right_boundary_port
        self.need_tcp_scan = need_tcp_scan
        self.need_udp_scan = need_udp_scan
        self.need_protocols_scan = need_protocols_scan
        self.threads_count = threads_count

    def scan(self):
        scanners = []

        threads_left = self.threads_count
        ports_count = self.right_boundary_port - self.left_boundary_port
        left = self.left_boundary_port

        for _ in range(self.threads_count):
            part = ports_count // threads_left
            right = left + part

            scanner = Scanner(self.host, left, right, self.need_tcp_scan, self.need_udp_scan, self.need_protocols_scan)
            scanners.append(scanner)
            scanner.start()

            threads_left -= 1
            ports_count -= part
            left = right

        for scanner in scanners:
            scanner.join()


class Scanner(threading.Thread):
    def __init__(self, host, left_boundary_port, right_boundary_port, need_tcp_scan, need_udp_scan, need_protocols_scan):
        super().__init__()
        self.host = host
        self.left_boundary_port = left_boundary_port
        self.right_boundary_port = right_boundary_port
        self.need_tcp_scan = need_tcp_scan
        self.need_udp_scan = need_udp_scan
        self.need_protocols_scan = need_protocols_scan
        self.open_ports = []
        self.closed_ports = []
        self.tcp_checkers = [(self.scan_http, 'http'), (self.scan_smtp, 'smtp'),
                             (self.scan_pop3, 'pop3')]
        self.udp_checkers = [(self.scan_dns, 'dns'), (self.scan_sntp, 'sntp')]

    def run(self):
        self.scan()

    def scan(self):
        scan_methods = []
        if self.need_tcp_scan:
            scan_methods.append((self.scan_tcp, 'tcp'))
        if self.need_udp_scan:
            scan_methods.append((self.scan_udp, 'udp'))
        for port in range(self.left_boundary_port, self.right_boundary_port):
            for scan_method, transport in scan_methods:
                is_open = scan_method(port)
                if is_open:
                    if self.need_protocols_scan:
                        protocol = self.protocols_scan(port, transport)
                        self.print_result(transport, port, protocol)
                    else:
                        self.print_result(transport, port)

    def scan_tcp(self, port):
        is_open = False
        addr = (self.host, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        res = sock.connect_ex(addr)
        if res == 0:
            self.open_ports.append(('tcp', port))
            is_open = True
        else:
            self.closed_ports.append(('tcp', port))
        sock.close()
        return is_open

    def scan_udp(self, port):
        is_open = False
        addr = (self.host, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(MESSAGE, addr)
        try:
            data, address = sock.recvfrom(1024)
        except ConnectionResetError:
            self.closed_ports.append(('udp', port))
        except socket.timeout:
            self.open_ports.append(('udp', port))
            is_open = True
        finally:
            sock.close()
        return is_open

    def print_result(self, transport, port, protocol=None):
        if protocol is not None:
            print(transport + '/' + str(port) + '(' + protocol +')')
        else:
            print(transport + '/' + str(port))

    def protocols_scan(self, port, conn):
        if conn == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            checkers = self.udp_checkers
        elif conn == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            checkers = self.tcp_checkers
        addr = (self.host, port)
        sock.settimeout(2)
        for scan_method, protocol_name in checkers:
            if scan_method(sock, addr):
                return protocol_name
        return None

    def send_data(self, sock, data, conn, addr):
        resp = b''
        try:
            if conn == 'udp':
                sock.sendto(data, addr)
                resp, _ = sock.recvfrom(BUFFER_SIZE)
            elif conn == 'tcp':
                sock.send(data)
                resp = sock.recv(BUFFER_SIZE)
        except socket.error:
            pass
        return resp

    def has_key_words(self, send_data, check_data, sock, conn, addr):
        resp = self.send_data(sock, send_data, conn, addr)
        for cdata in check_data:
            if cdata in resp:
                return True
        return False

    def check_if_correct(self, resp):
        return resp not in [None, b'']

    def scan_smtp(self, sock, addr):
        return self.has_key_words(b'EHLO a', [b'smtp', b'SMTP'], sock, 'tcp', addr)

    def scan_sntp(self, sock, addr):
        ntp_request = b'\xe3\x00\x03\xfa' + b'\x00\x01\x00\x00' * 2 + 28 * b'\x00'
        ntp_request += struct.pack('!I ', self.get_current_time()) + b'\x00' * 4
        resp = self.send_data(sock, ntp_request, 'udp', addr)
        return self.check_if_correct(resp)

    def scan_dns(self, sock, addr):
        google = b'\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00'
        dns_query = (b'\xb9\x73\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                     b'\x03\x77\x77\x77') + google + b'\x00\x01\x00\x01'
        resp = self.send_data(sock, dns_query, 'udp', addr)
        return self.check_if_correct(resp) and google in resp

    def scan_pop3(self, sock, addr):
        return self.has_key_words(b'test', [b'+OK POP', b'+OK pop'], sock, 'tcp', addr)

    def scan_http(self, sock, addr):
        return self.has_key_words(b'ping\r\n', [b'HTTP'], sock, 'tcp', addr)

    def get_current_time(self):
        diff = datetime.datetime.utcnow() - datetime.datetime(1900, 1, 1, 0, 0, 0)
        return diff.days * 24 * 60 * 60 + diff.seconds


def read_json_file(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except (FileNotFoundError, FileExistsError):
        return None


def main():
    conf = read_json_file('conf.json')
    threads_count = 5 if conf['threads_count'] < 5 else conf['threads_count']
    scanner_manager = ScanManager(conf['host'], conf['left_boundary_port'],
                                  conf['right_boundary_port'], conf['need_tcp_scan'],
                                  conf['need_udp_scan'], conf['need_protocols_scan'],
                                  threads_count)
    scanner_manager.scan()


if __name__ == '__main__':
    main()

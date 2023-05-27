import socket

from whois_record import WhoisRecord

PRIMARY_IANA_ADDRESS = "whois.iana.org"
CHUNK_SIZE = 1024
WHOIS_HEADERS = ['country', 'origin', 'originas']


class WhoisTracer:
    """
    Класс WhoisTracer служит для получения информации whois по IP-адресу.

    Атрибуты:
    ------------------------
    whois_info - словарь с информацией whois (страна, автономная система и т.д.)
    """
    def __init__(self):
        self.whois_info = {}

    def get_whois_data(self, address: str) -> WhoisRecord:
        """
        Получает информацию whois по заданному IP-адресу и возвращает объект WhoisRecord.
        :param address:
        :return: Объект WhoisRecord.
        """
        primary_sock = self.create_new_socket()
        primary_sock.connect((socket.gethostbyname(PRIMARY_IANA_ADDRESS), 43))
        primary_sock.send(f"{address}\r\n".encode('utf-8'))
        self.whois_info.clear()
        with primary_sock:
            whois_server = self.get_target_server(primary_sock.recv(CHUNK_SIZE))
            if whois_server:
                whois_sock = self.create_new_socket()
                whois_sock.connect((whois_server, 43))
                whois_sock.send(f"{address}\r\n".encode('utf-8'))
                data = bytearray()
                curr_chunk = whois_sock.recv(CHUNK_SIZE)
                while curr_chunk:
                    data += curr_chunk
                    curr_chunk = whois_sock.recv(CHUNK_SIZE)
                self.parse_whois_info(data)
        return WhoisRecord(address, self.whois_info)

    @staticmethod
    def create_new_socket() -> socket.socket:
        """
        Создает сокет TCP для подключения к whois серверу.
        :return: Сокет
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        return sock

    @staticmethod
    def get_target_server(raw_data: bytes) -> str:
        """
        Получает из первоначального ответа whois сервера primary_sock адрес подходящего whois сервера.
        :param raw_data:
        :return: Адрес подходящего whois сервера.
        """
        decoded_data = raw_data.decode()
        result = None
        if 'refer' in decoded_data:
            refer_ind = decoded_data.index('refer')
            decoded_data = decoded_data[refer_ind:].split('\n')[0].replace(' ', '').split(':')
            result = decoded_data[1]
        return result

    def parse_whois_info(self, raw_data: bytearray):
        """
        Анализирует полученные данные whois и заполняет соответствующие поля атрибута whois_info.
        :param raw_data:
        """
        decoded_data = raw_data.decode().lower()
        for el in WHOIS_HEADERS:
            if el in decoded_data:
                ind = decoded_data.index(el)
                record = decoded_data[ind:].split('\n')[0]
                record = record.replace(' ', '').split(':')
                self.whois_info[record[0]] = record[1]

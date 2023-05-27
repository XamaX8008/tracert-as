import socket

from typing import List

from packets.icmp_packet import IcmpPacket
from packets.whois_record import WhoisRecord
from whois_tracer import WhoisTracer


class Traceroute:
    """
    Класс Traceroute запускает процедуру traceroute для заданного хоста для определения маршрута и промежуточных узлов.

    Атрибуты:
    --------------------------------
    _host : IP-адрес, для которого будет выполняться traceroute.

    max_ttl: Максимальное значение Time-to-live.

    ttl: Текущее значение Time-to-live, которое увеличивается на каждой итерации.

    whois_tracer: Экземпляр WhoisTracer для получения информации whois о промежуточных узлах.
    """
    def __init__(self, host: str, max_ttl: int):
        self._host = socket.gethostbyname(host)
        self.max_ttl = max_ttl
        self.ttl = 1
        self.whois_tracer = WhoisTracer()

    def make_trace(self) -> List[WhoisRecord]:
        """
        Выполняет процедуру traceroute от _host для определения маршрута и промежуточных узлов.
        :return: Список объектов WhoisRecord, представляющих промежуточные узлы в маршруте.
        """
        result = []
        while self.ttl <= self.max_ttl:
            sender_sock, receiver_sock = self.get_new_sockets()
            icmp_pack = IcmpPacket(8, 0)
            sender_sock.sendto(bytes(icmp_pack), (self._host, 80))
            try:
                data, address = receiver_sock.recvfrom(1024)
            except (socket.timeout, socket.gaierror):
                result.append(None)
                self.ttl += 1
                continue
            trace_node = self.whois_tracer.get_whois_data(address[0])
            result.append(trace_node)
            received_icmp = IcmpPacket.from_bytes(data[20:])
            if self.check_icmp(received_icmp):
                sender_sock.close()
                receiver_sock.close()
                break
            self.ttl += 1
            sender_sock.close()
            receiver_sock.close()
        return result

    @staticmethod
    def check_icmp(icmp: IcmpPacket) -> bool:
        """
        Проверяет, содержит ли полученный ICMP-пакет сообщение Time Exceeded.
        :param icmp:
        :return: Если тип и код ICMP равны 0 True, иначе False.
        """
        if icmp.type == icmp.code == 0:
            return True
        return False

    def get_new_sockets(self) -> (socket.socket, socket.socket):
        """
        Создает новые сокеты для отправки и получения ICMP-пакетов.
        :return: Кортеж (send_socket, receive_socket).
        """
        send_sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM,
                                  socket.IPPROTO_ICMP)
        send_sock.setsockopt(socket.SOL_IP,
                             socket.IP_TTL,
                             self.ttl)
        recv_sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_RAW,
                                  socket.IPPROTO_ICMP)
        recv_sock.settimeout(2)
        return send_sock, recv_sock

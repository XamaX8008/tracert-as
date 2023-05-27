import struct
import random


class IcmpPacket:
    """
    Класс IcmpPacket представляет ICMP пакет.

    Атрибуты:
    --------------------------------
    type - тип ICMP пакета

    code - код ICMP пакета
    """
    def __init__(self, icmp_type: int, icmp_code: int):
        self.type = icmp_type
        self.code = icmp_code

    @classmethod
    def from_bytes(cls, data: bytes):
        """
        Десериализует байтовую строку в объект IcmpPacket.
        :param data:
        :return: Объект класса IcmpPacket
        """
        icmp_type, icmp_code = struct.unpack('!BB', data[:2])
        return cls(icmp_type, icmp_code)

    @classmethod
    def get_checksum(cls, msg: bytes) -> int:
        """
        Вычисляет контрольную сумму для данных ICMP пакета.
        :param msg:
        :return: Контрольная сумма
        """
        checksum = 0
        for i in range(0, len(msg), 2):
            part = (msg[i] << 8) + (msg[i + 1])
            checksum += part
        checksum = (checksum >> 16) + (checksum & 0xffff)

        return checksum ^ 0xffff

    def __bytes__(self) -> bytes:
        """
        Возвращает байтовую строку представления ICMP пакета с подсчитанной контрольной суммой.
        :return: Байтовая строка
        """
        mock_data = struct.pack('!BBH', self.type, self.code, 0)
        current_sum = self.get_checksum(mock_data)
        return struct.pack('!BBHHH', self.type, self.code,
                           current_sum, 1, random.randint(256, 3000))

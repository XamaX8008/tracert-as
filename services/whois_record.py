import socket


class WhoisRecord:
    """
    Класс WhoisRecord представляет объект с информацией whois.

    Атрибуты:
    ------------------------
    address - IP адрес

    name - имя хоста

    country - страна

    auto_sys - автономная система
    """
    def __init__(self, address: str, whois_data: dict):
        """
        Инициализирует атрибуты из IP-адреса и словаря whois_data.
        :param address:
        :param whois_data:
        """
        self.address = address
        self.name = ''
        try:
            self.name = socket.gethostbyaddr(address)[0]
        except socket.herror:
            pass
        self.country = ''
        self.auto_sys = ''
        if 'country' in whois_data and 'EU' not in whois_data["country"]:
            self.country = whois_data["country"]
        if 'origin' in whois_data:
            self.auto_sys = whois_data['origin']
        if 'originas' in whois_data:
            self.auto_sys = whois_data['originas']

    def _make_result_str(self) -> str:
        """
        Формирует строку с результатом в следующем порядке приоритета:

        имя хоста

        автономная система

        страна
        :return: Строка с результатом
        """
        result = f'{self.address}\n'
        if self.name and not self.auto_sys and not self.country:
            result += f'{self.name}\n'
        elif self.name:
            result += f'{self.name}, '
        if self.auto_sys and not self.country:
            result += f'{self.auto_sys}\n'
        elif self.auto_sys:
            result += f'{self.auto_sys}, '
        if self.country:
            result += f'{self.country}\n'
        return result

    def __str__(self) -> str:
        """
        Возвращает строку с результатом, вызывая _make_result_str.
        :return: Строка с результатом
        """
        return self._make_result_str()

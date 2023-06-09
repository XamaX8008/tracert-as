# tracert-as
tracert-as - это утилита командной строки для трассировки маршрута пакетов до заданного хоста с получением данных WHOIS для каждого прыжка.

# Установка
Для работы утилиты требуется Python версии 3.6 или выше.

* Склонируйте репозиторий:


```bash
git clone https://github.com/your_username/tracert-as.git
```

* Установите зависимости:

```bash
pip install -r requirements.txt
```

# Использование
Запустите файл tracert_as.py и передайте ему имя хоста, до которого требуется выполнить трассировку:

### Windows
```cmd
python tracert_as.py example.com
```

### Linux
```bash
python3 tracert_as.py example.com
```

По умолчанию, максимальное число прыжков равно 25. Чтобы изменить это значение, используйте аргумент --ttl:

### Windows
```cmd
python tracert_as.py example.com --ttl 30
```

### Linux
```bash
python3 tracert_as.py example.com --ttl 30
```

В результате выполнения команды будут выведены записи WHOIS для каждого прыжка на маршруте до целевого хоста. Если запись WHOIS не может быть получена для какого-либо прыжка, соответствующий элемент списка будет равен None.

Утилита использует протокол ICMP и отправляет пакеты с увеличивающимся значением TTL до тех пор, пока не будет достигнут максимальный предел или не будет получен ICMP-пакет с типом и кодом, равными 0, что означает успешную доставку пакета до целевого хоста.

В процессе выполнения каждого прыжка на маршруте, утилита также получает данные WHOIS для адреса получателя и сохраняет их в объекте WhoisRecord, который возвращается в списке результатов трассировки.
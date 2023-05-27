import argparse


def prepare_args() -> argparse.Namespace:
    """
    Подготавливает и парсит аргументы командной строки.

    :return: argparse.Namespace
        Объект, содержащий значения аргументов командной строки.
    """
    arg_parser = argparse.ArgumentParser(
        prog='tracert-as',
        description='A tool for '
    )
    arg_parser.add_argument('hostname', type=str, help="Hostname to trace")
    arg_parser.add_argument("--ttl", type=int, help="Max hops count",
                            default=25)

    return arg_parser.parse_args()

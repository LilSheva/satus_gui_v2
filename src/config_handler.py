# ==================================================================================
# МОДУЛЬ 1: УПРАВЛЕНИЕ КОНФИГУРАЦИЕЙ (Версия 2, со сложной логикой правил)
# Отвечает за создание, чтение и запись config.ini.
# Включает парсер для преобразования структурированных правил в удобный формат.
# ==================================================================================

import configparser
import os
from typing import List, Dict, Any

# Используем константу для имени файла
CONFIG_FILE_NAME = "config.ini"


def create_default_config(base_path: str):
    """
    Создает config.ini со сложной структурой правил, если он не существует.
    """
    config_path = os.path.join(base_path, CONFIG_FILE_NAME)

    if not os.path.exists(config_path):
        print(f"Файл конфигурации не найден. Создаем новый: {config_path}")
        config = configparser.ConfigParser()

        config['Paths'] = {
            'vulnerabilities': '',
            'ppts_local': '',
            'ppts_general': '',
            'journal': '',
            'output_folder': ''
        }

        config['Settings'] = {
            'min_word_length': '3',
            'prefix_threshold_short': '100',
            'prefix_threshold_medium': '90',
            'prefix_threshold_long': '80',
            'fuzz_ratio_threshold': '60',
            'min_matched_words': '2',
            'index1_results_limit': '5'
        }

        # --- Секции со структурированными правилами ---

        config['DA'] = {
            '; Формат: ИмяПравила = Вендор;Продукт;ID_ППТС;Приоритет(0 или 1)': '',
            '; Priority=1 означает, что если найден Вендор, статус присваивается немедленно, игнорируя всё остальное.': '',
            '; Если часть не нужна (например, Продукт), оставьте ее пустой: Вендор;;ID;1': '',
            'ExampleRuleDA': 'Exempl Vendor;Exempl Product;ID-12345;0'
        }

        config['Uslovno'] = {
            '; Формат: ИмяПравила = Вендор;Продукт;Приоритет(0 или 1)': '',
            '; Статус будет "Условно", ID ППТС всегда "-----------"': '',
            'UslovnoRule1': 'Cisco;IOS XE;;0',
            'UslovnoRule2': 'Microsoft;Visual Studio;;0',
        }

        config['NOT'] = {
            '; Формат: ИмяПравила = Вендор;Продукт;Приоритет(0 или 1)': '',
            '; Статус будет "НЕТ", ID ППТС всегда "-----------"': '',
            'WordPressPriorityRule': 'WordPress;;1',
            'AnotherNotRule': 'Joomla;;0'
        }

        config['LINUX'] = {
            '; Формат: ИмяПравила = Вендор;Продукт;ID_ППТС;НовоеНазваниеПродукта': '',
            '; Статус будет "Linux". Если ID_ППТС пусто, используется "-----------".': '',
            '; НовоеНазваниеПродукта используется для замены в отчете, если указано.': '',
            'KernelRule': 'Linux;Kernel;ID-LINUX-KERNEL;Linux Kernel',
            'UbuntuRule': 'Canonical Ltd;Ubuntu;ID-LINUX-UBUNTU;'
        }

        with open(config_path, 'w', encoding='utf-8') as configfile:
            config.write(configfile)


def load_config(base_path: str) -> configparser.ConfigParser:
    """Загружает конфигурацию из config.ini."""
    config_path = os.path.join(base_path, CONFIG_FILE_NAME)
    config = configparser.ConfigParser()
    config.read(config_path, encoding='utf-8')
    return config


def save_config(base_path: str, config_object: configparser.ConfigParser):
    """Сохраняет объект конфигурации в файл config.ini."""
    config_path = os.path.join(base_path, CONFIG_FILE_NAME)
    with open(config_path, 'w', encoding='utf-8') as configfile:
        config_object.write(configfile)
    print(f"Конфигурация сохранена в {config_path}")


def parse_structured_config_section(config: configparser.ConfigParser, section_name: str) -> List[Dict[str, Any]]:
    """
    Парсит секцию конфига со сложными правилами в список словарей.

    Args:
        config: Загруженный объект конфигурации.
        section_name: Название секции для парсинга ([DA], [NOT] и т.д.).

    Returns:
        Список словарей, где каждый словарь - это одно разобранное правило.
    """
    rules_list = []
    if not config.has_section(section_name):
        return rules_list

    for key, value in config.items(section_name):
        # Игнорируем комментарии, которые мы добавили для пояснения
        if key.startswith(';'):
            continue

        parts = [p.strip() for p in value.split(';')]
        rule = {'rule_name': key}

        # Используем безопасное извлечение с проверкой на количество элементов
        if section_name == 'DA':
            rule['vendor'] = parts[0] if len(parts) > 0 else ''
            rule['product'] = parts[1] if len(parts) > 1 else ''
            rule['id_ppts'] = parts[2] if len(parts) > 2 else ''
            rule['priority'] = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
        elif section_name in ['Uslovno', 'NOT']:
            rule['vendor'] = parts[0] if len(parts) > 0 else ''
            rule['product'] = parts[1] if len(parts) > 1 else ''
            rule['priority'] = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        elif section_name == 'LINUX':
            rule['vendor'] = parts[0] if len(parts) > 0 else ''
            rule['product'] = parts[1] if len(parts) > 1 else ''
            rule['id_ppts'] = parts[2] if len(parts) > 2 else ''
            rule['new_name'] = parts[3] if len(parts) > 3 else ''

        rules_list.append(rule)

    return rules_list


# --- Пример использования (для тестирования модуля) ---
if __name__ == '__main__':
    print("Тестирование модуля config_handler (v2)...")

    # 1. Создаем конфиг по умолчанию (если его нет)
    create_default_config('.')

    # 2. Загружаем его
    my_config = load_config('.')

    # 3. Парсим секцию [NOT] и выводим результат
    print("\n--- Парсинг секции [NOT] ---")
    not_rules = parse_structured_config_section(my_config, 'NOT')
    for r in not_rules:
        print(r)
    # Ожидаемый вывод:
    # {'rule_name': 'wordpresspriorityrule', 'vendor': 'WordPress', 'product': '', 'priority': 1}
    # {'rule_name': 'anothernotrule', 'vendor': 'Joomla', 'product': '', 'priority': 0}

    # 4. Парсим секцию [DA]
    print("\n--- Парсинг секции [DA] ---")
    da_rules = parse_structured_config_section(my_config, 'DA')
    for r in da_rules:
        print(r)
    # Ожидаемый вывод:
    # {'rule_name': 'exampleruleda', 'vendor': 'Exempl Vendor', 'product': 'Exempl Product', 'id_ppts': 'ID-12345', 'priority': 0}

    # 5. Парсим секцию [LINUX]
    print("\n--- Парсинг секции [LINUX] ---")
    linux_rules = parse_structured_config_section(my_config, 'LINUX')
    for r in linux_rules:
        print(r)
    # Ожидаемый вывод:
    # {'rule_name': 'kernelrule', 'vendor': 'Linux', 'product': 'Kernel', 'id_ppts': 'ID-LINUX-KERNEL', 'new_name': 'Linux Kernel'}
    # {'rule_name': 'ubunturule', 'vendor': 'Canonical Ltd', 'product': 'Ubuntu', 'id_ppts': 'ID-LINUX-UBUNTU', 'new_name': ''}
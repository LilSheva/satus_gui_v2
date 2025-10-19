# ==================================================================================
# МОДУЛЬ 4: СИНХРОНИЗАЦИЯ С ЖУРНАЛОМ
# Отвечает за поиск уязвимости по CVE в уже существующем Журнале Публикаций,
# чтобы определить, является ли уязвимость повторной.
# ==================================================================================

import pandas as pd
from typing import List, Dict, Any


def find_cve_in_journal(cve_id: str, journal_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Ищет точное совпадение CVE в DataFrame'е Журнала Публикаций.

    Args:
        cve_id (str): Идентификатор CVE для поиска (например, 'CVE-2024-45283').
        journal_df (pd.DataFrame): DataFrame с данными ЖП, загруженный data_loader'ом.

    Returns:
        Список словарей, где каждый словарь представляет найденную в ЖП строку.
        Возвращает пустой список, если совпадений не найдено или входные данные некорректны.
    """
    # Проверка на корректность входных данных
    if journal_df.empty or 'cve' not in journal_df.columns or not isinstance(cve_id, str):
        return []

    # Иногда в Excel-файлах CVE могут быть с лишними пробелами. Очистим и их.
    # Применяем .str для векторизованных строковых операций
    clean_cve_series = journal_df['cve'].str.strip()

    # Ищем все строки, где очищенное значение в столбце 'cve' совпадает с cve_id
    matches_df = journal_df[clean_cve_series == cve_id.strip()]

    # Возвращаем результат в виде списка словарей для удобной итерации
    return matches_df.to_dict('records')


# --- Пример использования (для тестирования модуля) ---
if __name__ == '__main__':
    print("--- Тестирование модуля journal_sync ---")

    # 1. Создаем тестовый DataFrame, имитирующий Журнал Публикаций
    mock_journal_data = {
        'responsible': ['Шейчук Я.И.', 'Иванов И.И.', 'Петров П.П.', 'Шейчук Я.И.'],
        'status': ['ДА', 'УСЛОВНО', 'НЕТ', 'ПОВТОР'],
        'id_ppts': ['COM-7303', 'COM-6888', '-----------', 'COM-7303'],
        'cve': ['CVE-2021-25743', 'CVE-2024-45283', 'CVE-2023-12345', '  CVE-2021-25743  '],  # Один CVE с пробелами
        'product': ['Google Inc, Kubernetes', 'SAP SE, SAP NetWeaver', 'Some Other Product', 'Google Kubernetes Old']
    }
    mock_journal_df = pd.DataFrame(mock_journal_data)

    # --- Тест 1: Ищем CVE, который существует (и даже дважды) ---
    cve_to_find_1 = "CVE-2021-25743"
    print(f"\nИщем: '{cve_to_find_1}'...")
    matches1 = find_cve_in_journal(cve_to_find_1, mock_journal_df)

    if matches1:
        print(f"Найдено совпадений: {len(matches1)}")
        for match in matches1:
            print(f"  -> {match}")
    else:
        print("Совпадений не найдено.")

    # Ожидаемый вывод: 2 совпадения.

    # --- Тест 2: Ищем CVE, который существует один раз ---
    cve_to_find_2 = "CVE-2024-45283"
    print(f"\nИщем: '{cve_to_find_2}'...")
    matches2 = find_cve_in_journal(cve_to_find_2, mock_journal_df)

    if matches2:
        print(f"Найдено совпадений: {len(matches2)}")
        for match in matches2:
            print(f"  -> {match}")
    else:
        print("Совпадений не найдено.")

    # Ожидаемый вывод: 1 совпадение.

    # --- Тест 3: Ищем CVE, которого нет в журнале ---
    cve_to_find_3 = "CVE-2025-99999"
    print(f"\nИщем: '{cve_to_find_3}'...")
    matches3 = find_cve_in_journal(cve_to_find_3, mock_journal_df)

    if matches3:
        print(f"Найдено совпадений: {len(matches3)}")
    else:
        print("Совпадений не найдено.")

    # Ожидаемый вывод: 0 совпадений.

    # --- Тест 4: Ищем в пустом DataFrame ---
    print("\nИщем в пустом DataFrame...")
    matches4 = find_cve_in_journal(cve_to_find_1, pd.DataFrame())

    if matches4:
        print(f"Найдено совпадений: {len(matches4)}")
    else:
        print("Совпадений не найдено.")

    # Ожидаемый вывод: 0 совпадений.
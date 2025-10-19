# ==================================================================================
# МОДУЛЬ 2: ЗАГРУЗЧИК ДАННЫХ
# Отвечает за чтение всех исходных XLSX файлов и их преобразование
# в стандартизированные DataFrame'ы для дальнейшей обработки.
# ==================================================================================

import pandas as pd
import os
from typing import List, Dict, Any


def load_vulnerabilities(path: str) -> pd.DataFrame:
    """
    Загружает ТСУ (таблицу с уязвимостями) из vulnerabilities.xlsx.
    Читает данные с первого листа файла.
    """
    try:
        required_cols = [0, 1, 2, 3, 4]
        col_names = ['id_num', 'cve', 'cvss', 'product', 'source_url']

        df = pd.read_excel(path, usecols=required_cols, header=None, skiprows=1, names=col_names, sheet_name=0)
        print(f"Успешно загружен файл ТСУ: {path}")
        return df
    except FileNotFoundError:
        print(f"ОШИБКА: Файл ТСУ не найден по пути: {path}")
    except Exception as e:
        print(f"ОШИБКА: Не удалось прочитать файл ТСУ '{path}'. Проверьте, что столбцы A-E существуют. Ошибка: {e}")
    return pd.DataFrame()


def load_ppts(local_path: str, general_path: str) -> pd.DataFrame:
    """
    Загружает локальный и общий ППТС (с первого листа каждого файла),
    объединяет их и приводит к единой структуре.
    """
    all_ppts = []

    if os.path.exists(local_path):
        try:
            local_df = pd.read_excel(local_path, usecols="O,Q,T", header=None, skiprows=1, sheet_name=0)
            local_df.columns = ['id_ppts', 'name', 'vendor']
            local_df['source'] = 'local'
            all_ppts.append(local_df)
            print(f"Успешно загружен локальный ППТС: {local_path}")
        except Exception as e:
            print(f"ОШИБКА: Не удалось прочитать локальный ППТС '{local_path}'. Проверьте столбцы O, Q, T. Ошибка: {e}")
    else:
        print(f"ИНФО: Локальный файл ППТС не найден по пути: {local_path}")

    if os.path.exists(general_path):
        try:
            general_df = pd.read_excel(general_path, usecols="M,O,R", header=None, skiprows=1, sheet_name=0)
            general_df.columns = ['id_ppts', 'name', 'vendor']
            general_df['source'] = 'general'
            all_ppts.append(general_df)
            print(f"Успешно загружен общий ППТС: {general_path}")
        except Exception as e:
            print(f"ОШИБКА: Не удалось прочитать общий ППТС '{general_path}'. Проверьте столбцы M, O, R. Ошибка: {e}")
    else:
        print(f"ИНФО: Общий файл ППТС не найден по пути: {general_path}")

    if not all_ppts:
        print("ОШИБКА: Не удалось загрузить ни один файл ППТС.")
        return pd.DataFrame()

    combined_df = pd.concat(all_ppts, ignore_index=True)
    combined_df['name'] = combined_df['name'].fillna('')
    combined_df['vendor'] = combined_df['vendor'].fillna('')
    combined_df.dropna(subset=['vendor', 'name'], how='all', inplace=True)

    print(f"ППТС объединены. Общее количество записей для анализа: {len(combined_df)}")
    return combined_df


def load_journal(path: str) -> pd.DataFrame:
    """
    Загружает Журнал Публикаций.
    Всегда читает данные с ПЕРВОГО листа в файле, независимо от его названия.
    """
    try:
        required_cols = "C,D,E,F,G,H,I"
        col_names = ['responsible', 'publication', 'status', 'id_ppts', 'cve', 'cvss', 'product']

        # <<< ИЗМЕНЕНИЕ ЗДЕСЬ: Вместо имени листа используем его индекс (0 - первый лист)
        df = pd.read_excel(path, sheet_name=0, usecols=required_cols, header=None, skiprows=1, names=col_names)

        print(f"Успешно загружен Журнал Публикаций (с первого листа): {path}")
        return df
    except FileNotFoundError:
        print(f"ОШИБКА: Файл ЖП не найден по пути: {path}")
    except ValueError as e:
        # Эта ошибка все еще может возникнуть, если файл пуст или поврежден
        print(f"ОШИБКА: Не удалось прочитать первый лист из файла '{path}'. Возможно, файл пуст/поврежден. Ошибка: {e}")
    except Exception as e:
        print(f"ОШИБКА: Не удалось прочитать файл ЖП '{path}'. Проверьте столбцы C,D,E,F,G,H,I. Ошибка: {e}")
    return pd.DataFrame()


# --- Пример использования (для тестирования модуля) ---
if __name__ == '__main__':
    print("--- Тестирование модуля data_loader ---")

    # !!! ВАЖНО: Замените эти пути на реальные пути к вашим тестовым файлам !!!
    VULNS_PATH = "C:/Users/yakov/PycharmProjects/test4/status_v2/vulnerabilities.xlsx"
    LOCAL_PPTS_PATH = "C:/Users/yakov/PycharmProjects/test4/status_v2/ppts_local.xlsx"
    GENERAL_PPTS_PATH = "C:/Users/yakov/PycharmProjects/test4/status_v2/ppts_general.xlsx"
    JOURNAL_PATH = "C:/Users/yakov/PycharmProjects/test4/status_v2/Журнал публикаций уязвимостей 15.10.2025.xlsx"

    print("\n--- 1. Загрузка таблицы уязвимостей ---")
    vulns_df = load_vulnerabilities(VULNS_PATH)
    if not vulns_df.empty:
        print("Структура DataFrame'а уязвимостей:")
        vulns_df.info()
        print("\nПервые 5 строк:")
        print(vulns_df.head())

    print("\n--- 2. Загрузка и объединение ППТС ---")
    ppts_df = load_ppts(LOCAL_PPTS_PATH, GENERAL_PPTS_PATH)
    if not ppts_df.empty:
        print("\nСтруктура объединенного DataFrame'а ППТС:")
        ppts_df.info()
        print("\nПримеры записей:")
        print(ppts_df.head())
        print(ppts_df.tail())

    print("\n--- 3. Загрузка Журнала Публикаций ---")
    journal_df = load_journal(JOURNAL_PATH)
    if not journal_df.empty:
        print("\nСтруктура DataFrame'а Журнала Публикаций:")
        journal_df.info()
        print("\nПервые 5 строк:")
        print(journal_df.head())
# ==================================================================================
# МОДУЛЬ 6: ГЕНЕРАТОР ОТЧЕТОВ (Версия 5, финальная, с исправлением merge)
# ==================================================================================

import pandas as pd
from typing import List, Dict, Any, Set
from datetime import datetime
import re


def _define_formats(workbook: Any) -> Dict[str, Any]:
    """Создает и возвращает словарь с форматами ячеек для xlsxwriter."""
    formats = {}

    formats['header'] = workbook.add_format({
        'bold': True, 'text_wrap': True, 'valign': 'vcenter', 'align': 'center',
        'fg_color': '#D7E4BC', 'border': 1
    })
    formats['green_vcenter_border'] = workbook.add_format({
        'bg_color': '#C6EFCE', 'valign': 'top', 'border': 1
    })
    formats['gray_vcenter_border'] = workbook.add_format({
        'bg_color': '#F2F2F2', 'valign': 'top', 'border': 1
    })
    formats['green_wrap_border'] = workbook.add_format({
        'bg_color': '#C6EFCE', 'valign': 'top', 'border': 1, 'text_wrap': True
    })
    formats['gray_wrap_border'] = workbook.add_format({
        'bg_color': '#F2F2F2', 'valign': 'top', 'border': 1, 'text_wrap': True
    })

    formats['bold_text'] = workbook.add_format({'bold': True})
    formats['bold_green_text'] = workbook.add_format({'bold': True, 'font_color': '#006100'})
    formats['underline_text'] = workbook.add_format({'underline': 1})

    return formats


def _format_rich_text_match(
        ppts_name_str: str, vuln_words_set: Set[str], min_word_len: int, formats: Dict
) -> list:
    """Формирует список для write_rich_string с выделением совпавших слов."""
    if not isinstance(ppts_name_str, str) or not ppts_name_str:
        return ['']

    rich_string_parts = []
    highlighted_once = set()
    words_and_delimiters = re.split(r'(\s+|-|,|\(|\))', ppts_name_str)

    for part in words_and_delimiters:
        if not part: continue

        cleaned_word = re.sub(r'[^\w]', '', part).lower()

        if not cleaned_word:
            rich_string_parts.append(part)
            continue

        if len(cleaned_word) >= min_word_len and cleaned_word in vuln_words_set:
            if cleaned_word not in highlighted_once:
                rich_string_parts.append(formats['bold_green_text'])
                highlighted_once.add(cleaned_word)
            else:
                rich_string_parts.append(formats['underline_text'])
        else:
            pass

        rich_string_parts.append(part)

    return rich_string_parts


def _create_main_sheet(
        writer: pd.ExcelWriter, processed_data: List[Dict], formats: Dict, responsible_person: str,
        publication_source: str
):
    """Создает лист 'Основная таблица'."""
    sheet_name = 'Основная таблица'
    today_date = datetime.now().strftime("%d.%m.%Y")

    main_data = []
    for item in processed_data:
        main_data.append({
            '№': item['source_data'].get('id_num', ''), 'Дата обработки': today_date,
            'Ответственный': responsible_person, 'Публикация': publication_source,
            'Статус': item.get('final_status', ''), 'ID ППТС': item.get('final_id', ''),
            'CVE': item['source_data'].get('cve', ''), 'CVSS': item['source_data'].get('cvss', ''),
            'Продукт': item['source_data'].get('product', ''), 'Источник': item['source_data'].get('source_url', '')
        })

    df = pd.DataFrame(main_data)
    df.to_excel(writer, sheet_name=sheet_name, index=False, header=False, startrow=1)

    worksheet = writer.sheets[sheet_name]
    worksheet.write_row('A1', list(df.columns), formats['header'])

    if responsible_person:
        worksheet.conditional_format(f'C2:C{len(df) + 1}', {'type': 'no_blanks', 'format': formats['bold_text']})

    widths = {'A': 5, 'B': 15, 'C': 20, 'D': 15, 'E': 12, 'F': 20, 'G': 20, 'H': 15, 'I': 60, 'J': 40}
    for col, width in widths.items():
        worksheet.set_column(f'{col}:{col}', width)


def _create_detailed_sheet(writer: pd.ExcelWriter, processed_data: List[Dict], formats: Dict, config: Any):
    """Создает лист 'Детальный анализ' с объединением ячеек для группировки."""
    sheet_name = 'Детальный анализ'
    worksheet = writer.book.add_worksheet(sheet_name)
    min_word_len = config.getint('Settings', 'min_word_length', fallback=3)

    header = [
        "№", "CVE", "CVSS", "Продукт", "Источник", "Статус (решение)", "ID ППТС (решение)",
        "Источник совпадения", "Совпадение: Имя", "Совпадение: Индекс", "Совпадение: ID ППТС",
        "Совпадение: Ответственный", "Совпадение: Статус",
    ]
    worksheet.write_row('A1', header, formats['header'])

    row_cursor = 1
    for item in processed_data:
        all_matches = []
        if item.get('status_source') == 'config':
            all_matches.append({'type': 'config', 'data': item['matched_rule']})
        all_matches.extend([{'type': 'journal', 'data': m} for m in item['journal_matches']])
        all_matches.extend([{'type': 'ppts', 'data': m} for m in item['ppts_matches']])

        num_matches = len(all_matches)

        is_decided = bool(item['final_status'])
        # Выбираем два типа формата: один для основных (левых) колонок, второй для колонок с совпадениями
        main_cell_format = formats['green_vcenter_border'] if is_decided else formats['gray_vcenter_border']
        match_cell_format = formats['green_wrap_border'] if is_decided else formats['gray_wrap_border']

        # Основная информация об уязвимости
        main_info = [
            item['source_data'].get('id_num', ''), item['source_data'].get('cve', ''),
            item['source_data'].get('cvss', ''), item['source_data'].get('product', ''),
            item['source_data'].get('source_url', ''), item.get('final_status', 'РУЧНОЙ АНАЛИЗ'),
            item.get('final_id', '')
        ]

        if num_matches == 0:
            worksheet.write_row(row_cursor, 0, main_info, main_cell_format)
            # Заполняем правую часть прочерками
            for i in range(7, len(header)):
                worksheet.write(row_cursor, i, '-', main_cell_format)
            row_cursor += 1
        elif num_matches == 1:
            # ИСПРАВЛЕНИЕ: Если совпадение одно, не объединяем, а просто пишем одну полную строку
            full_row = main_info + _get_match_row_data(all_matches[0], item, formats, min_word_len)

            # Записываем все ячейки с нужными форматами
            for col_idx, cell_data in enumerate(full_row):
                fmt = main_cell_format if col_idx < 7 else match_cell_format
                if isinstance(cell_data, list):  # Это наш rich_text
                    worksheet.write_blank(row_cursor, col_idx, None, fmt)
                    worksheet.write_rich_string(row_cursor, col_idx, *cell_data)
                else:
                    worksheet.write(row_cursor, col_idx, cell_data, fmt)
            row_cursor += 1
        else:  # num_matches > 1
            # ИСПРАВЛЕНИЕ: Объединяем ячейки только если строк больше одной
            start_row = row_cursor
            end_row = row_cursor + num_matches - 1

            for col_idx, data in enumerate(main_info):
                worksheet.merge_range(start_row, col_idx, end_row, col_idx, data, main_cell_format)

            for match_info in all_matches:
                match_row_data = _get_match_row_data(match_info, item, formats, min_word_len)
                for col_idx_offset, cell_data in enumerate(match_row_data):
                    col_idx_abs = 7 + col_idx_offset
                    if isinstance(cell_data, list):
                        worksheet.write_blank(row_cursor, col_idx_abs, None, match_cell_format)
                        worksheet.write_rich_string(row_cursor, col_idx_abs, *cell_data)
                    else:
                        worksheet.write(row_cursor, col_idx_abs, cell_data, match_cell_format)
                row_cursor += 1

    # Настройка ширины
    widths = {'A': 5, 'B': 18, 'C': 10, 'D': 50, 'E': 25, 'F': 15, 'G': 18, 'H': 20, 'I': 50, 'J': 12, 'K': 18, 'L': 20,
              'M': 12}
    for i, width in enumerate(widths.values()):
        col_letter = chr(ord('A') + i)
        worksheet.set_column(f'{col_letter}:{col_letter}', width)


def _get_match_row_data(match_info: Dict, item: Dict, formats: Dict, min_word_len: int) -> list:
    """Вспомогательная функция для получения данных для правых колонок таблицы."""
    match_type = match_info['type']
    match_data = match_info['data']

    if match_type == 'config':
        return ['Конфиг', match_data['raw'], 'Правило', match_data['id'], '', '']
    elif match_type == 'journal':
        return ['Журнал Публикаций', match_data['product'], 'N/A', match_data['id_ppts'], match_data['responsible'],
                match_data['status']]
    elif match_type == 'ppts':
        full_ppts_name = f"{match_data['vendor']} - {match_data['name']}"
        rich_text = _format_rich_text_match(full_ppts_name, item.get('vuln_words_set', set()), min_word_len, formats)
        return ['ППТС', rich_text, match_data['index'], match_data['id_ppts'], '', '']
    return ['' for _ in range(6)]  # Возвращаем пустые ячейки на всякий случай


def generate_report(
        processed_data_list: List[Dict], output_path: str, config: Any,
        responsible_person: str = "", publication_source: str = ""
):
    """Основная функция (Версия 5, финальная)."""
    try:
        with pd.ExcelWriter(output_path, engine='xlsxwriter') as writer:
            workbook = writer.book
            formats = _define_formats(workbook)

            _create_main_sheet(writer, processed_data_list, formats, responsible_person, publication_source)
            _create_detailed_sheet(writer, processed_data_list, formats, config)

        print(f"Отчет успешно сохранен в: {output_path}")
    except Exception as e:
        print(f"ОШИБКА: Не удалось создать отчет. Проверьте, что файл не открыт в другой программе. Ошибка: {e}")


if __name__ == '__main__':
    from configparser import ConfigParser

    mock_config = ConfigParser()
    mock_config.add_section('Settings')
    mock_config.set('Settings', 'min_word_length', '3')

    # Тестовые данные, в точности повторяющие ваш случай
    mock_processed_data = [
        {
            'source_data': {'id_num': 1, 'cve': 'CVE-2025-0001', 'product': 'Microsoft - Windows 10 and Windows 11',
                            'cvss': '8.8 High'},
            'final_status': '', 'final_id': '', 'journal_matches': [],
            'ppts_matches': [
                {'index': 3, 'id_ppts': 'WIN-11', 'vendor': 'Microsoft', 'name': 'Windows 11 Pro'},
                {'index': 2, 'id_ppts': 'WIN-SRV', 'vendor': 'Microsoft', 'name': 'Windows Server'}
            ],
            'vuln_words_set': {'microsoft', 'windows', '10', '11'}, 'status_source': 'ppts_match'
        },
        {
            'source_data': {'id_num': 2, 'cve': 'CVE-2025-0002', 'product': 'Super Old Java Vulnerability',
                            'cvss': '7.5 High'},
            'final_status': 'ПОВТОР', 'final_id': '', 'ppts_matches': [],
            'journal_matches': [
                {'status': 'ДА', 'id_ppts': 'JAVA-ID', 'product': 'Oracle Java SE', 'responsible': 'Иванов И.И.'}],
            'vuln_words_set': {'super', 'old', 'java', 'vulnerability'}, 'status_source': 'journal'
        },
        {
            'source_data': {'id_num': 3, 'cve': 'CVE-2025-0003', 'product': 'WordPress Plugin XYZ',
                            'cvss': '9.8 Critical'},
            'final_status': 'НЕТ', 'final_id': '-----------', 'journal_matches': [],
            'ppts_matches': [
                {'index': 1, 'id_ppts': 'WP-PLUGIN-GENERIC', 'vendor': '', 'name': 'Generic WordPress Plugin'}],
            'vuln_words_set': {'wordpress', 'plugin', 'xyz'}, 'status_source': 'config',
            'matched_rule': {'raw': 'WordPress;;1', 'id': 'wordpresspriorityrule'}
        }
    ]

    print("--- Тестирование модуля report_generator (v5) ---")
    generate_report(
        processed_data_list=mock_processed_data,
        output_path='./test_report_v6.xlsx',
        config=mock_config,
        responsible_person="Шейчук Я.И.",
        publication_source="БДУ ФСТЭК"
    )
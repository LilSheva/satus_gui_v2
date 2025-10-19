# ==================================================================================
# МОДУЛЬ 8: ГЕНЕРАТОР ТЕКСТА ПИСЬМА (Версия 5, финальная)
# Формирует структурированный HTML-код для вставки в Outlook.
# Использует iterrows() для 100% надежного доступа к столбцам.
# ==================================================================================
import pandas as pd
from typing import Dict, Any


def generate_email_parts(
        added_vulnerabilities_df: pd.DataFrame,
        publication_source: str,
        journal_date_str: str,
        total_vulns_count: int
) -> Dict[str, str]:
    """
    Создает все части письма (получатели, тема, тело в формате HTML).
    """

    # --- 1. Формирование полей "Кому", "Копия", "Тема" ---
    to_field = "Бабенко Александр Михайлович"
    copy_field = "Козырев Дмитрий Александрович; Ахидов Игорь Викторович; Денисов Андрей Владимирович (ЛУКОЙЛ-Технологии); Широлапов Михаил Васильевич"
    subject = f"Анализ публикаций уязвимостей {publication_source} (от {journal_date_str})"

    # --- 2. Подготовка данных для тела письма ---
    processed_count = len(added_vulnerabilities_df)

    status_colors = {
        "ДА": "#FF0000", "ПОВТОР": "#FF0000", "УСЛОВНО": "#FFA500",
        "LINUX": "#0070C0", "НЕТ": "#008000"
    }

    # --- 3. Генерация HTML-строк для таблицы (ИСПРАВЛЕНО) ---
    table_rows_html = ""
    # Мы не сортируем DataFrame здесь, он уже отсортирован по статусам
    df_for_email = added_vulnerabilities_df

    # ИСПОЛЬЗУЕМ .iterrows() ДЛЯ НАДЕЖНОГО ДОСТУПА К СТОЛБЦАМ ПО ИМЕНИ
    for i, row in enumerate(df_for_email.itertuples(), start=1):
        # Получаем данные, используя getattr для работы с itertuples
        # Pandas заменяет пробелы и спецсимволы на '_', поэтому 'ID ППТС' -> 'ID_ППТС'

        def get_value(r, col_name, default=''):
            # Пробуем получить значение с заменой пробела на '_'
            val = getattr(r, col_name.replace(' ', '_'), default)
            # Если значение - это pandas._libs.missing.NAType, возвращаем default
            return default if pd.isna(val) else str(val)

        status_val = get_value(row, 'Статус')
        id_ppts_val = get_value(row, 'ID ППТС')
        publication_val = get_value(row, 'Публикация')
        cve_val = get_value(row, 'CVE')
        cvss_val = get_value(row, 'CVSS')
        product_val = get_value(row, 'Продукт')
        source_val = get_value(row, 'Источник')

        status_color = status_colors.get(status_val.upper(), '#000000')

        table_rows_html += f"""
        <tr>
            <td style="text-align:center; border:1px solid #dddddd; background-color:#f2f2f2;"><b>{i}</b></td>
            <td style="text-align:center; border:1px solid #dddddd;">{publication_val}</td>
            <td style="text-align:center; border:1px solid #dddddd;"><font color="{status_color}">{status_val}</font></td>
            <td style="text-align:center; border:1px solid #dddddd;">{id_ppts_val}</td>
            <td style="text-align:left; border:1px solid #dddddd;">{cve_val}</td>
            <td style="text-align:left; border:1px solid #dddddd;">{cvss_val}</td>
            <td style="text-align:left; border:1px solid #dddddd;">{product_val}</td>
            <td style="text-align:left; border:1px solid #dddddd;">{source_val}</td>
        </tr>
        """
    # --- 4. Сборка финального HTML-тела письма ---
    body_html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Calibri, sans-serif; font-size: 11pt; }}
            p {{ margin: 0 0 10px 0; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ padding: 8px; text-align: left; border: 1px solid #dddddd; }}
        </style>
    </head>
    <body>
        <p>Добрый день!</p>
        <p>Проведён поиск публикаций уязвимостей на интернет-ресурсе {publication_source}.<br>
        Выявлены новые публикации уязвимостей в количестве «{total_vulns_count}» из них обработано «{processed_count}».<br>
        Проведён первичный анализ публикаций уязвимостей на предмет соответствия спискам ПТПС ЛУКОЙЛ.<br>
        Результаты приведены в таблице.</p>

        <table border="1">
            <thead>
                <tr style="background-color:#595959; color:white;">
                    <th style="text-align:center;"><b>№</b></th><th style="text-align:center;"><b>Публикация</b></th>
                    <th style="text-align:center;"><b>Статус</b></th><th style="text-align:center;"><b>ID ПТПС</b></th>
                    <th style="text-align:center;"><b>CVE</b></th><th style="text-align:center;"><b>CVSS</b></th>
                    <th style="text-align:center;"><b>Продукт</b></th><th style="text-align:center;"><b>Источник</b></th>
                </tr>
            </thead>
            <tbody>{table_rows_html}</tbody>
        </table>

        <p>&nbsp;</p>

        <p><font color="{status_colors.get('ДА', '#000')}"><b>ДА</b></font> – Продукт присутствует в ПТПС<br>
        <font color="{status_colors.get('УСЛОВНО', '#000')}"><b>Условно</b></font> – Продукт отсутствует в ПТПС, при этом известно, что продукт используется или допускается к использованию<br>
        <font color="{status_colors.get('LINUX', '#000')}"><b>Linux</b></font> – Продукт отсутствует в ПТПС. Не исключено, что уязвимый пакет Linux либо ядро Linux присутствует в инсталляции.<br>
        <font color="{status_colors.get('НЕТ', '#000')}"><b>НЕТ</b></font> – Продукт отсутствует в ПТПС</p>
    </body>
    </html>
    """

    return {'to': to_field, 'copy': copy_field, 'subject': subject, 'body_html': body_html.strip()}


# --- Пример использования (для тестирования модуля) ---
if __name__ == '__main__':
    mock_added_data = {
        '№': [3786, 3785, 3784],
        'Дата обработки': ['16.10.2025', '16.10.2025', '16.10.2025'],
        'Ответственный': ['Шейчук Я.И.', 'Шейчук Я.И.', 'Шейчук Я.И.'],
        'Публикация': ['БДУ ФСТЭК', 'БДУ ФСТЭК', 'БДУ ФСТЭК'],
        'Статус': ['ДА', 'УСЛОВНО', 'НЕТ'],
        'ID ППТС': ['ID-12345', 'ID-USLOVNO-XYZ', '-----------'],
        'CVE': ['CVE-2025-0001', 'CVE-2025-0003', 'CVE-2025-0002'],
        'CVSS': ['9.8 Critical', '6.5 Medium', '7.5 High'],
        'Продукт': ['Важный Продукт', 'Продукт для условной обработки', 'Неиспользуемый Продукт'],
        'Источник': ['https://bdu.fstec.ru/vul/1', 'https://bdu.fstec.ru/vul/3', 'https://bdu.fstec.ru/vul/2']
    }
    mock_df = pd.DataFrame(mock_added_data)

    print("--- Тестирование модуля email_generator (v5) ---")

    email_parts = generate_email_parts(
        added_vulnerabilities_df=mock_df,
        publication_source="БДУ ФСТЭК",
        journal_date_str="16.10.2025",
        total_vulns_count=15
    )

    print("\n--- ГОТОВЫЕ ЧАСТИ ПИСЬМА ---")
    print(f"Кому: {email_parts['to']}")
    print(f"Копия: {email_parts['copy']}")
    print(f"Тема: {email_parts['subject']}")

    with open("email_preview.html", "w", encoding="utf-8") as f:
        f.write(email_parts['body_html'])

    print("\nТело письма сохранено в файл 'email_preview.html'.")
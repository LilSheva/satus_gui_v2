# ==================================================================================
# МОДУЛЬ 3: ДВИЖОК СРАВНЕНИЯ
# Реализует сложную логику нечеткого сопоставления названий продуктов.
# Является "мозгом" аналитического процесса.
# ==================================================================================

import re
from fuzzywuzzy import fuzz
from typing import Set, Dict, Any, Tuple, List
import pandas as pd


def _prepare_words(text: str, min_word_length: int) -> Set[str]:
    """Вспомогательная функция для очистки и подготовки текста."""
    if not isinstance(text, str) or not text:
        return set()

    text = text.lower()
    text = re.sub(r'\d+', '', text)  # Удаляем все цифры
    text = re.sub(r'[^\w\s]', ' ', text)  # Удаляем знаки препинания

    words = {word for word in text.split() if len(word) >= min_word_length}
    return words


def _split_vuln_product(vuln_product_name: str) -> Tuple[str, str]:
    """Разделяет название уязвимого ПО на вендора и продукт."""
    if " - " in vuln_product_name:
        parts = vuln_product_name.split(" - ", 1)
        return parts[0], parts[1]
    elif "," in vuln_product_name:
        parts = vuln_product_name.split(",", 1)
        return parts[0], parts[1]
    else:
        return "", vuln_product_name


def _compare_word_sets(vuln_words: Set[str], ppts_words: Set[str], settings: Dict[str, int]) -> Dict[str, Any]:
    """Сравнивает два множества слов и возвращает метрики совпадения."""
    match_count = 0
    total_similarity = 0
    prefix_match_found = False

    if not vuln_words or not ppts_words:
        return {'count': 0, 'avg_sim': 0, 'prefix_found': False}

    for v_word in vuln_words:
        best_match_score = 0
        is_prefix = False

        for p_word in ppts_words:
            # 1. Проверка по префиксу
            len_v = len(v_word)
            if p_word.startswith(v_word):
                threshold = settings['prefix_threshold_short'] if len_v < 5 else \
                    settings['prefix_threshold_medium'] if len_v < 10 else \
                        settings['prefix_threshold_long']
                # Для префикса считаем схожесть 100%
                if threshold == 100:  # По сути, полное совпадение
                    best_match_score = 100
                    is_prefix = True
                    break  # Нашли идеальное совпадение, идем к следующему слову

            # 2. Нечеткое сравнение (если префикс не найден)
            ratio = fuzz.ratio(v_word, p_word)
            if ratio > best_match_score:
                best_match_score = ratio

        if best_match_score >= settings['fuzz_ratio_threshold']:
            match_count += 1
            total_similarity += best_match_score
            if is_prefix:
                prefix_match_found = True

    avg_sim = (total_similarity / match_count) if match_count > 0 else 0
    return {'count': match_count, 'avg_sim': avg_sim, 'prefix_found': prefix_match_found}


def find_best_matches(vuln_product_name: str, ppts_df: pd.DataFrame, config: Any) -> List[Dict[str, Any]]:
    """
    Основная функция сравнения. Принимает название продукта из ТСУ,
    DataFrame всех ППТС и настройки. Возвращает отсортированный список совпадений.
    """
    results = []

    # Загружаем настройки из конфига с значениями по умолчанию
    s = config['Settings']
    settings = {
        'min_word_length': s.getint('min_word_length', 3),
        'prefix_threshold_short': s.getint('prefix_threshold_short', 100),
        'prefix_threshold_medium': s.getint('prefix_threshold_medium', 90),
        'prefix_threshold_long': s.getint('prefix_threshold_long', 80),
        'fuzz_ratio_threshold': s.getint('fuzz_ratio_threshold', 60),
        'min_matched_words': s.getint('min_matched_words', 2),
        'index1_results_limit': s.getint('index1_results_limit', 5)
    }

    vendor_str, product_str = _split_vuln_product(vuln_product_name)
    vuln_vendor_words = _prepare_words(vendor_str, settings['min_word_length'])
    vuln_product_words = _prepare_words(product_str, settings['min_word_length'])

    for row in ppts_df.itertuples(index=False):
        ppts_full_string = f"{row.vendor} {row.name}"
        ppts_words = _prepare_words(ppts_full_string, settings['min_word_length'])

        if not ppts_words:
            continue

        vendor_res = _compare_word_sets(vuln_vendor_words, ppts_words, settings)
        product_res = _compare_word_sets(vuln_product_words, ppts_words, settings)

        total_matches = vendor_res['count'] + product_res['count']

        if total_matches == 0:
            continue

        avg_similarity = (vendor_res['avg_sim'] * vendor_res['count'] + product_res['avg_sim'] * product_res[
            'count']) / total_matches

        # Расчет Индекса
        index = 0
        if vendor_res['prefix_found'] and product_res['prefix_found']:
            index = 3
        elif vendor_res['prefix_found'] or product_res['prefix_found']:
            index = 2
        elif total_matches > 0:
            index = 1

        if index >= 1 and total_matches >= settings['min_matched_words']:
            results.append({
                'id_ppts': row.id_ppts,
                'name': row.name,
                'vendor': row.vendor,
                'source': row.source,
                'index': index,
                'matched_words_count': total_matches,
                'avg_similarity': round(avg_similarity),
                'vendor_matched': vendor_res['count'],
                'product_matched': product_res['count']
            })

    # Сортировка: по Индексу (убыв), по кол-ву слов (убыв), по схожести (убыв)
    results.sort(key=lambda x: (-x['index'], -x['matched_words_count'], -x['avg_similarity']))

    # Ограничение для Индекса 1
    index1_results = [r for r in results if r['index'] == 1]
    other_results = [r for r in results if r['index'] > 1]

    final_results = other_results + index1_results[:settings['index1_results_limit']]
    final_results.sort(key=lambda x: (-x['index'], -x['matched_words_count'], -x['avg_similarity']))

    return final_results


# --- Пример использования (для тестирования модуля) ---
if __name__ == '__main__':
    from configparser import ConfigParser

    # 1. Создаем тестовый DataFrame ППТС
    mock_ppts_data = {
        'id_ppts': ['ID-001', 'ID-002', 'ID-003', 'ID-004', 'ID-005'],
        'vendor': ['Microsoft', 'Apache', 'Google', 'Oracle', 'Microsoft'],
        'name': ['Windows Server 2019', 'Tomcat', 'Chrome Browser', 'Java', 'Windows 11 Pro'],
        'source': ['local', 'general', 'local', 'general', 'local']
    }
    mock_ppts_df = pd.DataFrame(mock_ppts_data)

    # 2. Создаем тестовый конфиг
    mock_config = ConfigParser()
    mock_config.add_section('Settings')
    mock_config.set('Settings', 'min_word_length', '3')
    mock_config.set('Settings', 'min_matched_words', '2')
    mock_config.set('Settings', 'fuzz_ratio_threshold', '85')  # Повысим для теста
    mock_config.set('Settings', 'index1_results_limit', '5')
    mock_config.set('Settings', 'prefix_threshold_short', '100')
    mock_config.set('Settings', 'prefix_threshold_medium', '90')
    mock_config.set('Settings', 'prefix_threshold_long', '80')

    # 3. Тестируемая строка
    test_vuln = "Microsoft - Windows 10 Enterprise"

    print(f"--- Тестирование движка сравнения для: '{test_vuln}' ---")

    # 4. Запускаем функцию
    best_matches = find_best_matches(test_vuln, mock_ppts_df, mock_config)

    # 5. Выводим результат
    if not best_matches:
        print("Совпадений не найдено.")
    else:
        for match in best_matches:
            print(
                f"Index: {match['index']}, "
                f"ID: {match['id_ppts']}, "
                f"Vendor: {match['vendor']}, "
                f"Name: {match['name']}, "
                f"Words: {match['matched_words_count']}, "
                f"Similarity: {match['avg_similarity']}%"
            )

    # Ожидаемый результат:
    # Сначала должны пойти Windows 11 и Windows Server (Index 3 или 2),
    # так как у них есть префиксное совпадение по "Microsoft" и "Windows".
    # Остальные продукты не должны появиться, так как не проходят пороги.
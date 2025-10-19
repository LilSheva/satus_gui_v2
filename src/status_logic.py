# ==================================================================================
# МОДУЛЬ 5: ЛОГИКА ПРИСВОЕНИЯ СТАТУСОВ
# "Мозг" приложения. Собирает результаты всех проверок (ЖП, конфиг, движок)
# и принимает финальное решение о статусе уязвимости, следуя четкому приоритету.
# ==================================================================================

from typing import List, Dict, Any, Optional

# Константы для ID по умолчанию, чтобы избежать опечаток
ID_NOT = "-----------"
ID_USLOVNO = "-----------"
ID_LINUX_DEFAULT = "-----------"


def _check_config_rules(
        product_name: str,
        config_rules: Dict[str, List[Dict]],
        priority_only: bool
) -> Optional[Dict[str, str]]:
    """
    Вспомогательная функция для проверки названия продукта по всем правилам из конфига.

    Args:
        product_name: Название уязвимого продукта.
        config_rules: Словарь с распарсенными правилами.
        priority_only: Если True, проверяет только правила с priority=1.

    Returns:
        Словарь со статусом и ID, если найдено совпадение, иначе None.
    """
    product_lower = product_name.lower()

    # Определяем порядок проверки секций
    rule_order = [('NOT', 'НЕТ'), ('DA', 'ДА'), ('LINUX', 'Linux'), ('Uslovno', 'УСЛОВНО')]

    for section_name, status in rule_order:
        for rule in config_rules.get(section_name, []):
            # Пропускаем, если проверяем только приоритетные, а у правила его нет
            if priority_only and rule.get('priority', 0) != 1:
                continue

            vendor_lower = rule.get('vendor', '').lower()
            prod_lower = rule.get('product', '').lower()

            # Правило сработает, если:
            # 1. Указан только вендор, и он есть в начале названия уязвимости.
            # 2. Указаны и вендор, и продукт, и оба содержатся в названии уязвимости.
            vendor_match = vendor_lower and vendor_lower in product_lower

            if vendor_match:
                # Если продукт в правиле не указан, или он тоже совпадает
                if not prod_lower or prod_lower in product_lower:
                    if status == 'НЕТ':
                        return {'status': status, 'id_ppts': ID_NOT}
                    if status == 'УСЛОВНО':
                        return {'status': status, 'id_ppts': ID_USLOVNO}
                    if status == 'ДА':
                        return {'status': status, 'id_ppts': rule.get('id_ppts', '')}
                    if status == 'Linux':
                        return {'status': status, 'id_ppts': rule.get('id_ppts') or ID_LINUX_DEFAULT}

    return None


def determine_status(
        vuln_data: Dict,
        journal_matches: List,
        ppts_matches: List,
        config_rules: Dict[str, List[Dict]]
) -> Dict[str, str]:
    """
    Определяет статус на основе всех имеющихся данных, следуя четкому приоритету.

    Args:
        vuln_data: Словарь с данными по уязвимости (нужен ключ 'product').
        journal_matches: Результат от journal_sync.
        ppts_matches: Результат от comparison_engine.
        config_rules: Словарь с распарсенными правилами из конфига.

    Returns:
        Словарь с финальным статусом и ID ППТС.
    """
    product_name = vuln_data.get('product', '')

    # 1. ПРОВЕРКА №1: Журнал Публикаций (высший приоритет)
    if journal_matches:
        return {'status': 'ПОВТОР', 'id_ppts': ''}

    # 2. ПРОВЕРКА №2: Безоговорочные правила из конфига (priority=1)
    priority_match = _check_config_rules(product_name, config_rules, priority_only=True)
    if priority_match:
        return priority_match

    # 3. ПРОВЕРКА №3: Результаты интеллектуального поиска
    if ppts_matches:
        # Найдены потенциальные совпадения, но нет уверенности - отдаем на ручной анализ
        return {'status': '', 'id_ppts': ''}

    # Сюда мы попадаем, только если ppts_matches ПУСТОЙ

    # 4. ПРОВЕРКА №4: Обычные правила из конфига (priority=0)
    non_priority_match = _check_config_rules(product_name, config_rules, priority_only=False)
    if non_priority_match:
        return non_priority_match

    # 5. ПРОВЕРКА №5: Финальный вердикт (ничего не найдено)
    return {'status': 'НЕТ', 'id_ppts': ID_NOT}


# --- Пример использования (для тестирования модуля) ---
if __name__ == '__main__':
    # --- ГОТОВИМ ТЕСТОВЫЕ ДАННЫЕ ---
    mock_config_rules = {
        'NOT': [{'vendor': 'WordPress', 'product': '', 'priority': 1}],
        'DA': [{'vendor': 'МойВендор', 'product': 'МойПродукт', 'id_ppts': 'ID-DA-123', 'priority': 0}],
        'LINUX': [{'vendor': 'Linux', 'product': 'Kernel', 'id_ppts': 'ID-LNX-001', 'new_name': ''}],
        'Uslovno': []
    }

    print("--- Тестирование модуля status_logic ---")

    # Тест 1: Сработал Журнал Публикаций
    print("\n[Тест 1]: Уязвимость найдена в ЖП")
    result = determine_status({}, journal_matches=[{'cve': 'CVE-123'}], ppts_matches=[], config_rules={})
    print(f"  -> Результат: {result}")
    assert result['status'] == 'ПОВТОР'

    # Тест 2: Сработало ПРИОРИТЕТНОЕ правило из конфига
    print("\n[Тест 2]: Сработало приоритетное правило 'NOT' для WordPress")
    result = determine_status(
        {'product': 'WordPress Plugin Contact Form 7'},
        journal_matches=[],
        ppts_matches=[{'id_ppts': 'какие-то найденные совпадения'}],  # Эти совпадения должны быть проигнорированы
        config_rules=mock_config_rules
    )
    print(f"  -> Результат: {result}")
    assert result['status'] == 'НЕТ'

    # Тест 3: Есть совпадения в ППТС, но правила не сработали -> Ручной анализ
    print("\n[Тест 3]: Правила не сработали, но есть совпадения в ППТС")
    result = determine_status(
        {'product': 'Microsoft Windows'},
        journal_matches=[],
        ppts_matches=[{'id_ppts': 'ID-WIN-11'}],
        config_rules=mock_config_rules
    )
    print(f"  -> Результат: {result}")
    assert result['status'] == ''

    # Тест 4: Нет совпадений в ППТС, но сработало ОБЫЧНОЕ правило
    print("\n[Тест 4]: Нет совпадений в ППТС, сработало обычное правило 'DA'")
    result = determine_status(
        {'product': 'Продукт от МойВендор, название МойПродукт'},
        journal_matches=[],
        ppts_matches=[],
        config_rules=mock_config_rules
    )
    print(f"  -> Результат: {result}")
    assert result['status'] == 'ДА' and result['id_ppts'] == 'ID-DA-123'

    # Тест 5: Ничего нигде не найдено
    print("\n[Тест 5]: Абсолютно ничего не найдено")
    result = determine_status(
        {'product': 'Неизвестный экзотический продукт'},
        journal_matches=[],
        ppts_matches=[],
        config_rules=mock_config_rules
    )
    print(f"  -> Результат: {result}")
    assert result['status'] == 'НЕТ'

    print("\n--- Все тесты пройдены успешно! ---")
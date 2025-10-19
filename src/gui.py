import customtkinter as ctk
from customtkinter import CTk, CTkFrame, CTkLabel, CTkEntry, CTkButton, CTkTabview, CTkProgressBar, CTkTextbox, CTkOptionMenu
import tkinter
import tkinter.filedialog as tkfd
import threading
import os
from src import (
    data_loader,
    comparison_engine,
    journal_sync,
    status_logic,
    report_generator,
    config_handler,
    journal_updater,
    email_generator
)


class VulnerabilityAnalyzerApp(CTk):
    def __init__(self, base_path):
        super().__init__()
        self.base_path = base_path
        self.title("Анализатор статусов уязвимостей")
        self.geometry("800x600")
        self.resizable(True, True)

        # Загружаем или создаём конфиг
        config_handler.create_default_config(self.base_path)
        self.config = config_handler.load_config(self.base_path)

        self.create_ui()
    def create_ui(self):
        print("Создание UI...")
        # Создаём вкладки
        self.tabview = CTkTabview(self, width=760, height=560)
        self.tabview.pack(pady=10, padx=10, fill="both", expand=True)

        self.tabview.add("Файлы")
        self.tabview.add("Настройки")
        self.tabview.add("Анализ")

        self.create_files_tab()
        self.create_settings_tab()
        self.create_analysis_tab()
        print("UI создана")

    def create_files_tab(self):
        tab = self.tabview.tab("Файлы")
        frame = CTkFrame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Поля для путей
        paths = [
            ("vulnerabilities", "Таблица с уязвимостями (ТСУ)"),
            ("ppts_local", "Локальный перечень ППТС"),
            ("ppts_general", "Общий перечень ППТС"),
            ("journal", "Журнал публикаций уязвимостей"),
            ("output_folder", "Папка для сохранения отчетов")
        ]

        self.entries = {}
        row = 0
        for key, label_text in paths:
            CTkLabel(frame, text=f"{label_text}:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
            entry = CTkEntry(frame, width=400)
            entry.grid(row=row, column=1, padx=5, pady=5)
            # Загружаем из конфига
            entry.insert(0, self.config.get('Paths', key, fallback=''))
            self.entries[key] = entry

            browse_btn = CTkButton(frame, text="Обзор", command=lambda k=key, e=entry: self.browse_file(k, e))
            browse_btn.grid(row=row, column=2, padx=5, pady=5)
            row += 1

        # Поля для ответственного и источника
        CTkLabel(frame, text="Ответственный:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
        self.responsible_entry = CTkEntry(frame)
        self.responsible_entry.grid(row=row, column=1, padx=5, pady=5)
        self.responsible_entry.insert(0, "Шейчук Я.И.")
        row += 1

        CTkLabel(frame, text="Источник публикации:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
        self.publication_entry = CTkEntry(frame)
        self.publication_entry.grid(row=row, column=1, padx=5, pady=5)
        self.publication_entry.insert(0, "БДУ ФСТЭК")

        # Кнопка сохранения конфига
        save_btn = CTkButton(frame, text="Сохранить настройки", command=self.save_config)
        save_btn.grid(row=row+1, column=1, pady=10)

    def create_settings_tab(self):
        tab = self.tabview.tab("Настройки")
        frame = CTkFrame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Настройки
        settings = [
            ("min_word_length", "Минимальная длина слова", 3, 1, 10),
            ("prefix_threshold_short", "Порог префикса короткие слова (%)", 100, 50, 100),
            ("prefix_threshold_medium", "Порог префикса средние слова (%)", 90, 50, 100),
            ("prefix_threshold_long", "Порог префикса длинные слова (%)", 80, 50, 100),
            ("fuzz_ratio_threshold", "Порог нечеткого совпадения (%)", 60, 0, 100),
            ("min_matched_words", "Минимальное количество совпавших слов", 2, 1, 10),
            ("index1_results_limit", "Лимит результатов индекс 1", 5, 1, 20)
        ]

        row = 0
        for key, label_text, default, min_val, max_val in settings:
            CTkLabel(frame, text=f"{label_text}:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
            entry = CTkEntry(frame)
            entry.grid(row=row, column=1, padx=5, pady=5)
            val = self.config.getint('Settings', key, fallback=default)
            entry.insert(0, str(val))
            self.entries[key] = entry
            row += 1

        # Кнопка сохранения
        save_btn = CTkButton(frame, text="Сохранить настройки", command=self.save_config)
        save_btn.grid(row=row, column=1, pady=10)

    def create_analysis_tab(self):
        tab = self.tabview.tab("Анализ")
        frame = CTkFrame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Кнопки
        btn_frame = CTkFrame(frame)
        btn_frame.pack(pady=10)
        self.analyze_btn = CTkButton(btn_frame, text="Запустить анализ", command=self.start_analysis)
        self.analyze_btn.pack(side="left", padx=10)
        self.update_btn = CTkButton(btn_frame, text="Обновить журнал и сгенерировать письмо", command=self.start_update)
        self.update_btn.pack(side="left", padx=10)

        # Прогресс
        self.progress = CTkProgressBar(frame, width=400)
        self.progress.pack(pady=10)
        self.progress.set(0)

        # Лог
        self.log_box = CTkTextbox(frame, width=750, height=300)
        self.log_box.pack(pady=10, padx=10)

    def browse_file(self, key, entry):
        if key == "output_folder":
            path = tkfd.askdirectory()
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)
        else:
            filetypes = [("Excel files", "*.xlsx"), ("All files", "*.*")]
            path = tkfd.askopenfilename(filetypes=filetypes)
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

    def save_config(self):
        # Сохраняем пути
        for key in ["vulnerabilities", "ppts_local", "ppts_general", "journal", "output_folder"]:
            self.config.set('Paths', key, self.entries[key].get())
        # Сохраняем настройки
        for key in ['min_word_length', 'prefix_threshold_short', 'prefix_threshold_medium',
                    'prefix_threshold_long', 'fuzz_ratio_threshold', 'min_matched_words', 'index1_results_limit']:
            val = self.entries[key].get()
            self.config.set('Settings', key, val)
        config_handler.save_config(self.base_path, self.config)
        self.add_log("Настройки сохранены.")

    def add_log(self, text):
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")

    def start_analysis(self):
        self.analyze_btn.configure(state="disabled")
        self.progress.set(0)
        self.add_log("Запуск анализа...")
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        try:
            # Получаем пути
            vulns_path = self.entries["vulnerabilities"].get()
            local_ppts = self.entries["ppts_local"].get()
            general_ppts = self.entries["ppts_general"].get()
            journal_path = self.entries["journal"].get()
            output_folder = self.entries["output_folder"].get()
            responsible = self.responsible_entry.get()
            publication = self.publication_entry.get()

            if not all([vulns_path, local_ppts, general_ppts, journal_path, output_folder]):
                self.add_log("Ошибка: Все пути должны быть указаны.")
                return

            output_path = os.path.join(output_folder, "res_tmp_report.xlsx")

            self.progress.set(0.1)
            self.add_log("Загрузка конфигурационных правил...")
            parsed_config_rules = {
                'DA': config_handler.parse_structured_config_section(self.config, 'DA'),
                'NOT': config_handler.parse_structured_config_section(self.config, 'NOT'),
                'LINUX': config_handler.parse_structured_config_section(self.config, 'LINUX'),
                'Uslovno': config_handler.parse_structured_config_section(self.config, 'Uslovno'),
            }

            self.progress.set(0.2)
            self.add_log("Загрузка данных...")
            vulns_df = data_loader.load_vulnerabilities(vulns_path)
            ppts_df = data_loader.load_ppts(local_ppts, general_ppts)
            journal_df = data_loader.load_journal(journal_path)
            if vulns_df.empty:
                self.add_log("Ошибка: Таблица с уязвимостями пуста.")
                return

            self.progress.set(0.3)
            all_results = []
            total = len(vulns_df)
            self.add_log(f"Начинаем анализ {total} уязвимостей...")
            for i, row in enumerate(vulns_df.itertuples()):
                vuln_data = {'product': row.product, 'cve': row.cve}
                journal_matches = journal_sync.find_cve_in_journal(vuln_data['cve'], journal_df)
                ppts_matches = comparison_engine.find_best_matches(vuln_data['product'], ppts_df, self.config)

                min_word_len = self.config.getint('Settings', 'min_word_length', fallback=3)
                vendor_str, product_str = comparison_engine._split_vuln_product(vuln_data['product'])
                vuln_words_set = comparison_engine._prepare_words(f"{vendor_str} {product_str}", min_word_len)

                status_info = status_logic.determine_status(
                    vuln_data=vuln_data, journal_matches=journal_matches,
                    ppts_matches=ppts_matches, config_rules=parsed_config_rules
                )

                status_source = ''
                matched_rule = None
                if status_info['status'] == 'ПОВТОР':
                    status_source = 'journal'
                elif status_info['status'] != '' and status_info['status'] != 'НЕТ':
                    status_source = 'config'
                elif ppts_matches and status_info['status'] == '':
                    status_source = 'ppts_match'
                elif status_info['status'] == 'НЕТ':
                    status_source = 'no_match'

                all_results.append({
                    'source_data': row._asdict(),
                    'final_status': status_info['status'], 'final_id': status_info['id_ppts'],
                    'journal_matches': journal_matches, 'ppts_matches': ppts_matches,
                    'vuln_words_set': vuln_words_set, 'status_source': status_source, 'matched_rule': matched_rule
                })

                self.progress.set(0.3 + (i / total) * 0.5)

            self.progress.set(0.9)
            self.add_log("Генерация отчета...")
            report_generator.generate_report(
                processed_data_list=all_results, output_path=output_path, config=self.config,
                responsible_person=responsible, publication_source=publication
            )

            self.progress.set(1.0)
            self.add_log(f"Анализ завершен. Отчет сохранен в {output_path}")

        except Exception as e:
            self.add_log(f"Ошибка во время анализа: {str(e)}")
        finally:
            self.analyze_btn.configure(state="normal")

    def start_update(self):
        self.update_btn.configure(state="disabled")
        self.progress.set(0)
        self.add_log("Запуск обновления журнала...")
        threading.Thread(target=self.run_update, daemon=True).start()

    def run_update(self):
        try:
            journal_path = self.entries["journal"].get()
            output_folder = self.entries["output_folder"].get()
            responsible = self.responsible_entry.get()
            publication = self.publication_entry.get()
            verified_report_path = os.path.join(output_folder, "res_tmp_report.xlsx")
            email_path = os.path.join(output_folder, "email_preview.html")

            if not os.path.exists(verified_report_path) or not os.path.exists(journal_path):
                self.add_log("Ошибка: Не найдены необходимые файлы.")
                return

            self.progress.set(0.1)
            self.add_log("Обновление журнала публикаций...")
            added_data_df = journal_updater.update_journal_file(journal_path, verified_report_path)

            if added_data_df is not None and not added_data_df.empty:
                self.progress.set(0.6)
                self.add_log("Генерация письма...")
                new_journal_name = journal_updater.generate_new_journal_name(journal_path)
                date_str = " ".join(new_journal_name.split(" ")[-1:]).split(".")[0]
                if "(" in date_str:
                    date_str = date_str.split(" (")[0]

                total_vulns_count = len(data_loader.load_vulnerabilities(self.entries["vulnerabilities"].get()))

                email_parts = email_generator.generate_email_parts(
                    added_vulnerabilities_df=added_data_df,
                    publication_source=publication,
                    journal_date_str=date_str,
                    total_vulns_count=total_vulns_count
                )

                with open(email_path, "w", encoding="utf-8") as f:
                    f.write(email_parts['body_html'])

                self.progress.set(1.0)
                self.add_log(f"Журнал обновлен. Письмо сохранено в {email_path}")
            else:
                self.add_log("Нет данных для обновления.")

        except Exception as e:
            self.add_log(f"Ошибка во время обновления: {str(e)}")
        finally:
            self.update_btn.configure(state="normal")

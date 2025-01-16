# py_md5
Алгоритм хеширования MD5

MD5 — криптографическая хеш-функция, преобразующая данные в 128-битный хеш (32 символа в HEX). Используется для проверки целостности данных.

## Основные шаги:

### Подготовка данных:
Дополнение данных до длины, кратной 512 битам.
Добавление длины исходных данных.
### Инициализация регистров:
Четыре 32-битных регистра (A, B, C, D) с начальными значениями.
### Обработка блоков:
Данные разбиваются на блоки по 512 бит.
Каждый блок обрабатывается в 4 раунда (64 шага) с использованием нелинейных функций и циклических сдвигов.
Формирование хеша:
Итоговый хеш — объединение значений регистров в 32-символьную HEX-строку.

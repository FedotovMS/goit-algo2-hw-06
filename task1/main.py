import mmh3


class BloomFilter:
    """
    Bloom Filter з бітовим зберіганням (мінімум пам'яті).
    size - кількість бітів
    num_hashes - кількість хешів (k)
    """

    def __init__(self, size: int, num_hashes: int):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size має бути додатнім цілим числом")
        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes має бути додатнім цілим числом")

        self.size = size
        self.num_hashes = num_hashes
        self._bits = bytearray((size + 7) // 8)  # зберігаємо біти компактно

    def _set_bit(self, idx: int) -> None:
        self._bits[idx >> 3] |= (1 << (idx & 7))

    def _get_bit(self, idx: int) -> int:
        return (self._bits[idx >> 3] >> (idx & 7)) & 1

    def _normalize(self, item) -> str:
        """
        Паролі обробляємо як рядки (як в ТЗ).
        Некоректні значення (None) повертаємо як порожній маркер.
        """
        if item is None:
            return ""
        if isinstance(item, str):
            return item
        return str(item)

    def add(self, item) -> bool:
        """
        Додає елемент у фільтр.
        Повертає False, якщо елемент некоректний (порожній після нормалізації).
        """
        s = self._normalize(item)
        if s.strip() == "":
            return False

        for i in range(self.num_hashes):
            idx = mmh3.hash(s, i, signed=False) % self.size
            self._set_bit(idx)
        return True

    def contains(self, item) -> bool:
        """
        Перевіряє, чи елемент МІГ бути раніше (можливі false-positive).
        Некоректні значення вважаємо такими, що "не містяться".
        """
        s = self._normalize(item)
        if s.strip() == "":
            return False

        for i in range(self.num_hashes):
            idx = mmh3.hash(s, i, signed=False) % self.size
            if self._get_bit(idx) == 0:
                return False
        return True


def check_password_uniqueness(bloom: BloomFilter, new_passwords) -> dict:
    """
    Перевіряє нові паролі на унікальність через BloomFilter.
    Повертає dict: {password_as_str: status}

    Статуси:
    - "вже використаний"
    - "унікальний"
    - "некоректний (порожній/None)"
    """
    results = {}

    for p in new_passwords:
        # ключ у dict — як рядок (щоб не падало на None / int тощо)
        key = "None" if p is None else (p if isinstance(p, str) else str(p))

        # окремо обробляємо некоректні
        if p is None or (isinstance(p, str) and p.strip() == ""):
            results[key] = "некоректний (порожній/None)"
            continue

        # перевірка
        if bloom.contains(p):
            results[key] = "вже використаний"
        else:
            results[key] = "унікальний"
            bloom.add(p)  # щоб наступні перевірки враховували цей пароль

    return results


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        if status == "вже використаний":
            print(f"Пароль '{password}' — вже використаний.")
        elif status == "унікальний":
            print(f"Пароль '{password}' — унікальний.")
        else:
            print(f"Пароль '{password}' — {status}.")
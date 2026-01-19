import hashlib
import ipaddress
import json
import math
import os
import time
from typing import Iterator, Optional, Tuple


# ---------- HyperLogLog ----------

class HyperLogLog:
    """
    Мінімальна реалізація HyperLogLog.
    p: кількість біт для індексації регістра, m = 2^p.
    """

    def __init__(self, p: int = 14) -> None:
        if not isinstance(p, int) or p < 4 or p > 18:
            raise ValueError("p має бути цілим у діапазоні [4, 18]")
        self.p = p
        self.m = 1 << p
        self.registers = bytearray(self.m)

        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1.0 + 1.079 / self.m)

    @staticmethod
    def _hash64(s: str) -> int:
        d = hashlib.sha256(s.encode("utf-8", errors="replace")).digest()
        return int.from_bytes(d[:8], "big", signed=False)

    @staticmethod
    def _clz64(x: int) -> int:
        return 64 - x.bit_length()

    def add(self, item: str) -> None:
        x = self._hash64(item)
        j = x >> (64 - self.p)
        w = (x << self.p) & ((1 << 64) - 1)

        if w == 0:
            rho = 64 - self.p + 1
        else:
            rho = self._clz64(w) + 1

        if rho > self.registers[j]:
            self.registers[j] = rho

    def count(self) -> float:
        inv_sum = 0.0
        zeros = 0
        for r in self.registers:
            inv_sum += 2.0 ** (-r)
            if r == 0:
                zeros += 1

        e = self.alpha * (self.m ** 2) / inv_sum

        # small range correction (linear counting)
        if e <= 2.5 * self.m and zeros > 0:
            e = self.m * math.log(self.m / zeros)

        # large range correction
        if e > (1.0 / 30.0) * (2.0 ** 64):
            e = -(2.0 ** 64) * math.log(1.0 - (e / (2.0 ** 64)))

        return e


# ---------- Log parsing (JSON lines) ----------

def _validate_ip(s: str) -> Optional[str]:
    s = s.strip()
    if not s:
        return None
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None


def _extract_client_ip(obj: dict) -> Optional[str]:
    """
    1) Якщо є http_x_forwarded_for -> беремо перший IP (реальний клієнт)
    2) Інакше fallback на remote_addr
    """
    xff = obj.get("http_x_forwarded_for", "")
    if isinstance(xff, str) and xff.strip():
        first = xff.split(",")[0].strip()
        ip = _validate_ip(first)
        if ip:
            return ip

    ra = obj.get("remote_addr", "")
    if isinstance(ra, str) and ra.strip():
        ip = _validate_ip(ra)
        if ip:
            return ip

    return None


def iter_ips_from_log(path: str) -> Iterator[str]:
    """
    Потоково читає лог, де кожен рядок — JSON.
    Ігнорує некоректні рядки (битий JSON / відсутній IP / невалідний IP).
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = _extract_client_ip(obj)
            if ip:
                yield ip


# ---------- Counting methods (streaming) ----------

def exact_unique_count_stream(path: str) -> int:
    seen = set()
    for ip in iter_ips_from_log(path):
        seen.add(ip)
    return len(seen)


def hll_unique_count_stream(path: str, p: int = 14) -> float:
    hll = HyperLogLog(p=p)
    for ip in iter_ips_from_log(path):
        hll.add(ip)
    return hll.count()


# ---------- Output table ----------

def print_comparison_table(exact: float, approx: float, t_exact: float, t_hll: float) -> None:
    header_left = ""
    col1 = "Точний підрахунок"
    col2 = "HyperLogLog"

    rows = [
        ("Унікальні елементи", f"{exact:.1f}", f"{approx:.1f}"),
        ("Час виконання (сек.)", f"{t_exact:.4f}", f"{t_hll:.4f}"),
    ]

    w0 = max(len(header_left), max(len(r[0]) for r in rows))
    w1 = max(len(col1), max(len(r[1]) for r in rows))
    w2 = max(len(col2), max(len(r[2]) for r in rows))

    print("Результати порівняння:")
    print(f"{header_left:<{w0}}  {col1:>{w1}}  {col2:>{w2}}")
    for r in rows:
        print(f"{r[0]:<{w0}}  {r[1]:>{w1}}  {r[2]:>{w2}}")


# ---------- Main ----------

if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    LOG_PATH = os.path.join(BASE_DIR, "lms-stage-access.log")

    if not os.path.exists(LOG_PATH):
        print(f"Файл не знайдено: {LOG_PATH}")
        raise SystemExit(1)

    t0 = time.perf_counter()
    exact = exact_unique_count_stream(LOG_PATH)
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    approx = hll_unique_count_stream(LOG_PATH, p=14)
    t3 = time.perf_counter()

    print_comparison_table(
        exact=float(exact),
        approx=float(approx),
        t_exact=(t1 - t0),
        t_hll=(t3 - t2),
    )
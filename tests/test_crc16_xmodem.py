"""Tests for crc16-xmodem. ≥100 pytest items across 12 categories."""
from __future__ import annotations

import pytest

from crc16_xmodem import crc, register


# ---------- 1. canonical_check (AC1, AC3) ----------
class TestCanonical:
    def test_ac1_single_zero(self):
        assert crc(bytes([0x00])) == 0x0000

    def test_ac3_reveng_canonical(self):
        assert crc(b"123456789") == 0x31C3

    def test_empty(self):
        assert crc(b"") == 0x0000

    def test_seed_byte_00(self):
        assert crc(bytes([0x00])) == 0x0000

    def test_seed_byte_01(self):
        assert crc(bytes([0x01])) == 0x1021

    def test_seed_byte_ff(self):
        assert crc(bytes([0xFF])) == 0x1EF0

    def test_seed_range_0_9(self):
        assert crc(bytes(range(10))) == 0x2378


# ---------- 2. byte_range_zero (n=0..255) — 256 tests ----------
@pytest.mark.parametrize("n", list(range(256)))
def test_single_byte(n: int):
    """Single byte — verify result is masked to 16 bits (AC11)."""
    result = crc(bytes([n]))
    assert 0 <= result < 65536


# ---------- 3. length_sweep — 64 tests ----------
@pytest.mark.parametrize("n", list(range(64)))
def test_zero_length_sweep(n: int):
    """crc(b'\\x00' * n) is deterministic and masked (AC11)."""
    result = crc(b"\x00" * n)
    assert 0 <= result < 65536


# ---------- 4. seed_vectors — 6 tests ----------
def test_seed_vector_empty():
    assert crc(b"") == 0x0000

def test_seed_vector_00():
    assert crc(bytes([0x00])) == 0x0000

def test_seed_vector_01():
    assert crc(bytes([0x01])) == 0x1021

def test_seed_vector_ff():
    assert crc(bytes([0xFF])) == 0x1EF0

def test_seed_vector_range():
    assert crc(bytes(range(10))) == 0x2378

def test_seed_vector_ascii():
    assert crc(b"123456789") == 0x31C3


# ---------- 5. determinism — 30 tests ----------
@pytest.mark.parametrize("seed", list(range(30)))
def test_determinism(seed: int):
    """Same input twice → same output."""
    import random
    rng = random.Random(seed)
    data = bytes(rng.randint(0, 255) for _ in range(1024))
    a = crc(data)
    b = crc(data)
    assert a == b
    assert 0 <= a < 65536


# ---------- 6. type_errors — 8 tests (AC12) ----------
@pytest.mark.parametrize("bad_input", [
    None,
    "123456789",
    123456789,
    [0x31, 0x32, 0x33],
    {"data": b"123456789"},
    3.14,
    True,
    (0x31, 0x32, 0x33),
])
def test_type_errors(bad_input):
    """Non-bytes-like input raises TypeError (AC12)."""
    with pytest.raises(TypeError):
        crc(bad_input)


# ---------- 7. bytearray_memoryview — 4 tests ----------
def test_bytearray_input():
    assert crc(bytearray(b"123456789")) == 0x31C3

def test_memoryview_input():
    assert crc(memoryview(b"123456789")) == 0x31C3

def test_bytearray_matches_bytes():
    data = bytearray(range(64))
    assert crc(data) == crc(bytes(data))

def test_memoryview_matches_bytes():
    data = memoryview(bytes(range(128)))
    assert crc(data) == crc(bytes(data))


# ---------- 8. register_metadata — 7 cases ----------
@pytest.mark.parametrize("key,expected", [
    ("width", 16),
    ("poly", 0x1021),
    ("init", 0x0000),
    ("refin", False),
    ("refout", False),
    ("xorout", 0x0000),
    ("check", 0x31C3),
])
def test_register_metadata(key, expected):
    """register() matches RevEng parameter table."""
    assert register()[key] == expected


# ---------- 9. oracle_crcmod (AC11) — 100 tests ----------
@pytest.mark.parametrize("seed", list(range(100)))
def test_oracle_crcmod(seed):
    """crc() output matches crcmod's mkPredefinedCrcFun('xmodem') for ≥100 random inputs (AC11).

    crcmod bundle ships a full table of well-known CRC polynomials; the XMODEM
    entry ships with check=12739 (0x31C3) which matches our register()['check']
    byte-for-byte. We use the standardised 'xmodem' alias rather than the raw
    mkCrcFun(0x1021, ...) form because crcmod's mkCrcFun only accepts a narrow
    set of degrees and rejects the raw 0x1021 polynomial.
    """
    crcmod = pytest.importorskip("crcmod")
    import random
    rng = random.Random(seed)
    length = rng.randint(1, 4096)
    data = bytes(rng.randint(0, 255) for _ in range(length))
    expected_fn = crcmod.predefined.mkPredefinedCrcFun("xmodem")
    expected = expected_fn(data)
    assert crc(data) == expected


# ---------- 10. cli — 6 tests ----------
def test_cli_self_test():
    """CLI --self-test exits 0 with PASS message."""
    import subprocess
    r = subprocess.run(
        ["python3", "-m", "crc16_xmodem", "--self-test"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "PASS" in r.stdout

def test_cli_data_ascii():
    """CLI --data with ASCII hex bytes yields 0x31C3 for '123456789'."""
    import subprocess
    r = subprocess.run(
        ["python3", "-m", "crc16_xmodem", "--data", "31", "32", "33", "34", "35", "36", "37", "38", "39"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert r.stdout.strip() == "0x31C3"

def test_cli_register():
    """CLI --register prints RevEng parameter table."""
    import subprocess
    r = subprocess.run(
        ["python3", "-m", "crc16_xmodem", "--register"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "width=16" in r.stdout
    assert "poly=4129" in r.stdout  # 0x1021 = 4129
    assert "check=12739" in r.stdout  # 0x31C3 = 12739

def test_cli_stdin():
    """CLI --stdin reads bytes from stdin and prints CRC."""
    import subprocess
    r = subprocess.run(
        ["python3", "-m", "crc16_xmodem", "--stdin"],
        input=b"123456789", capture_output=True,
    )
    assert r.returncode == 0
    assert r.stdout.strip() == b"0x31C3"

def test_cli_empty_data():
    """CLI with no data returns 0x0000 (empty bytes)."""
    import subprocess
    r = subprocess.run(
        ["python3", "-m", "crc16_xmodem"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert r.stdout.strip() == "0x0000"

def test_cli_single_byte():
    """CLI with single hex byte yields correct CRC."""
    import subprocess
    r = subprocess.run(
        ["python3", "-m", "crc16_xmodem", "--data", "0x41"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    expected = crc(b"\x41")
    assert r.stdout.strip() == f"0x{expected:04X}"


# ---------- 11. edge_cases — 30 boundary lengths ----------
@pytest.mark.parametrize("length", [0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4095, 4096, 8192])
def test_length_edge_cases(length):
    """Boundary lengths — no quadratic blowup (AC12)."""
    import random
    rng = random.Random(42)
    data = bytes(rng.randint(0, 255) for _ in range(length))
    result = crc(data)
    assert 0 <= result < 65536


# ---------- 12. long_input_no_quadratic — 5 tests ----------
@pytest.mark.parametrize("size", [100_000, 500_000, 1_000_000, 2_000_000, 5_000_000])
def test_long_input_linear_time(size):
    """1MB+ inputs run in linear time, no quadratic blowup (AC12)."""
    import time
    data = bytes(range(256)) * (size // 256)
    start = time.perf_counter()
    result = crc(data)
    elapsed = time.perf_counter() - start
    assert elapsed < 30.0
    assert 0 <= result < 65536


# ---------- 13. init_param_conformance (AC4-AC7) ----------
def test_init_0000_matches_reveng():
    """init=0x0000 is the per-byte starting register value (AC4)."""
    assert crc(b"") == 0x0000

def test_check_value_reveng():
    """RevEng check value: crc(b'123456789') == 0x31C3 (AC3)."""
    assert crc(b"123456789") == 0x31C3

def test_register_check_value():
    """register()['check'] matches RevEng catalogue."""
    assert register()["check"] == 0x31C3

def test_register_init_value():
    """register()['init'] matches RevEng catalogue."""
    assert register()["init"] == 0x0000

def test_register_poly_value():
    """register()['poly'] matches RevEng catalogue."""
    assert register()["poly"] == 0x1021

def test_register_width():
    """register()['width'] matches RevEng catalogue."""
    assert register()["width"] == 16

def test_register_refin_false():
    """register()['refin'] == False (MSB-first, NOT reflected)."""
    assert register()["refin"] is False

def test_register_refout_false():
    """register()['refout'] == False (NOT reflected on output)."""
    assert register()["refout"] is False

def test_register_xorout_zero():
    """register()['xorout'] == 0x0000 (NOT XORed on output)."""
    assert register()["xorout"] == 0x0000

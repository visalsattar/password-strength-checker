from password_checker import check, load_common

COMMON = load_common()


def label(pw):
    return check(pw, COMMON)[0]


def test_too_short_is_weak():
    assert label("Ab1!") == "Weak"


def test_leaked_password_is_weak_even_if_complex_looking():
    assert "password1" in COMMON
    assert label("Password1") == "Weak"  # case-insensitive match


def test_medium():
    assert label("Visal2026x") == "Medium"  # 10 chars, 3 types


def test_strong():
    assert label("Blue#Kite7River") == "Strong"  # 15 chars, 4 types


def test_long_single_type_not_strong():
    assert label("purplemonkeydishwasher") == "Medium"


def test_unicode_counts():
    lbl, score, _, _ = check("Çaylak-Şifre-2026", COMMON)
    assert lbl == "Strong" and score == 6


def test_tips_name_missing_types():
    tips = check("lowercaseonly", COMMON)[3]
    assert "Add at least one uppercase letter." in tips and "Add at least one number." in tips

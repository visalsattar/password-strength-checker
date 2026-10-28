# Password Strength Checker

A command-line tool that rates a password **Weak**, **Medium** or **Strong** and tells you how to improve it. Built as Project 1 of the DecodeLabs Cybersecurity internship.

## How it rates a password

| Check | Result |
|---|---|
| Shorter than 8 characters | Weak (instant fail) |
| Appears in a list of 10,000 leaked passwords (case-insensitive) | Weak |
| Otherwise: +1 for each character type used (lowercase, uppercase, number, symbol), +1 for 12+ characters, +1 for 16+ | 5–6 Strong, 3–4 Medium, 0–2 Weak |

It also prints a rough entropy estimate (`length × log2(character pool)`). This is an upper bound: it assumes the characters were chosen at random, and human-chosen passwords rarely are.

## Security choices

- **Hidden input:** the password is read with `getpass`, so it doesn't appear on screen or in terminal scrollback.
- **Never printed or saved:** the tool shows only the rating and tips, never the password.
- **Leaked-password check:** `P@ssword1` passes every "has upper, digit, symbol" rule but sits at the top of attackers' wordlists. The wordlist is SecLists' `10k-most-common.txt`.
- **Unicode-aware:** `str.isupper()`, `isdigit()` and related methods handle non-English letters, so `Çaylak-Şifre-2026` is scored correctly.
- **Known limit, memory:** Python strings are immutable and can't be wiped from RAM. `del` only drops the reference. A production system would handle secrets in a mutable `bytearray` or in a lower-level language.

## Run

```bash
python password_checker.py
python -m pytest -q        # 7 tests
```

## Not covered (possible next steps)

- Keyboard patterns (`qwerty`) and repeated or sequential characters (`aaaa`, `1234`)
- Online breach lookup through the Have I Been Pwned k-anonymity API
- A full estimator such as `zxcvbn`

## Credits

`common_passwords.txt` is `Passwords/Common-Credentials/10k-most-common.txt` from [SecLists](https://github.com/danielmiessler/SecLists) (Copyright (c) 2018 Daniel Miessler), used under the MIT License.

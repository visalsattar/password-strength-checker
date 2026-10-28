"""Password Strength Checker: rates a password Weak, Medium or Strong.

Rules:
  1. Shorter than 8 characters        -> Weak (instant fail)
  2. Found in a list of 10,000 leaked -> Weak (attackers try these first)
  3. Otherwise score = character types used (lowercase, uppercase, digit, symbol)
     + 1 if length >= 12, + 1 if length >= 16
     score >= 5 -> Strong, score >= 3 -> Medium, else Weak
"""
import math
from getpass import getpass
from pathlib import Path

MIN_LENGTH = 8
WORDLIST = Path(__file__).with_name("common_passwords.txt")


def load_common(path=WORDLIST):
    try:
        return {line.strip().lower() for line in path.open(encoding="utf-8", errors="ignore") if line.strip()}
    except FileNotFoundError:
        print(f"Warning: {path.name} not found, leaked-password check disabled.")
        return set()


def check(password, common=frozenset()):
    """Return (label, score, entropy_bits, tips). Never prints or stores the password."""
    classes = {
        "lowercase letter": any(c.islower() for c in password),
        "uppercase letter": any(c.isupper() for c in password),
        "number": any(c.isdigit() for c in password),
        "symbol": any(not c.isalnum() for c in password),
    }
    pool = 26 * classes["lowercase letter"] + 26 * classes["uppercase letter"] + 10 * classes["number"] + 33 * classes["symbol"]
    # rough upper bound: assumes characters were picked at random, which humans rarely do
    entropy = round(len(password) * math.log2(pool), 1) if pool else 0.0
    tips = [f"Add at least one {name}." for name, present in classes.items() if not present]

    if len(password) < MIN_LENGTH:
        return "Weak", 0, entropy, [f"Use at least {MIN_LENGTH} characters (yours has {len(password)})."] + tips
    if password.lower() in common:
        return "Weak", 0, entropy, ["This password appears in a public leaked-password list. Pick a different one."]

    score = sum(classes.values()) + (len(password) >= 12) + (len(password) >= 16)
    if len(password) < 12:
        tips.append("Use 12 or more characters; length adds the most strength.")
    label = "Strong" if score >= 5 else "Medium" if score >= 3 else "Weak"
    return label, score, entropy, tips


def main():
    common = load_common()
    print("Password Strength Checker (input is hidden; press Enter on an empty line to quit)")
    while True:
        password = getpass("Password: ")
        if not password:
            break
        label, score, entropy, tips = check(password, common)
        print(f"Strength: {label}  (score {score}/6, ~{entropy} bits)")
        for tip in tips:
            print(f"  - {tip}")
        del password  # drops our reference; Python strings can't be wiped from RAM (see README)


if __name__ == "__main__":
    main()

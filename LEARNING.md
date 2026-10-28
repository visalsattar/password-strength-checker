# Learning notes

Read this until you can explain every line without looking. "Walk me through your code" is a standard interview question.

## The constants

```python
MIN_LENGTH = 8
WORDLIST = Path(__file__).with_name("common_passwords.txt")
```
`Path(__file__)` is the path of this script. `.with_name(...)` swaps the file name, so the wordlist is always found next to the script, whatever folder you run it from. A plain `"common_passwords.txt"` would only work if you ran the script from its own folder.

## `load_common(path=WORDLIST)`

```python
return {line.strip().lower() for line in path.open(encoding="utf-8", errors="ignore") if line.strip()}
```
Read inside out:
- `path.open(...)` yields the file one line at a time. `errors="ignore"` skips bytes that aren't valid UTF-8 instead of crashing. Leaked-password lists often contain junk bytes.
- `line.strip()` removes the newline and surrounding spaces.
- `.lower()` stores every entry in lowercase, so the check can be case-insensitive.
- `if line.strip()` skips empty lines.
- The `{...}` braces build a **set**. Checking `x in some_set` takes the same time whether the set holds 10 or 10 million items (a hash lookup). A list would scan every entry.

```python
except FileNotFoundError:
    print(f"Warning: {path.name} not found, leaked-password check disabled.")
    return set()
```
If the wordlist is missing, the tool keeps working without that check. This is **fail-open**: a missing file silently makes the tool weaker. It's acceptable for a learning CLI. In a real login system you'd fail closed (refuse to run) so nobody can weaken the checks by deleting a file.

## `check(password, common=frozenset())`

```python
classes = {
    "lowercase letter": any(c.islower() for c in password),
    "uppercase letter": any(c.isupper() for c in password),
    "number": any(c.isdigit() for c in password),
    "symbol": any(not c.isalnum() for c in password),
}
```
For each character type, `any(...)` stops at the first match and returns `True` or `False`. "Symbol" means anything that isn't a letter or digit, so a space and an emoji both count. The keys are written as readable phrases on purpose: they're reused in the tips.

`common=frozenset()` is the default. An empty frozenset is immutable, so it's safe as a default argument. A mutable default like `[]` or `set()` is shared between calls, a classic Python bug.

```python
pool = 26 * classes["lowercase letter"] + 26 * classes["uppercase letter"] + 10 * classes["number"] + 33 * classes["symbol"]
```
`bool` is a subclass of `int`: `True` is 1 and `False` is 0. So `26 * True` is 26 and `26 * False` is 0. The pool is how many different characters an attacker would have to try per position. 33 is the number of printable ASCII symbols including space (95 printable characters minus 62 letters and digits).

```python
entropy = round(len(password) * math.log2(pool), 1) if pool else 0.0
```
Entropy in bits = length × log2(pool). Each bit doubles the number of guesses. The `if pool` guard avoids `log2(0)`, which raises an error for an empty password. This number assumes every character was picked at random. Humans don't pick that way, so it **overestimates** real strength. `Password2026!` shows 85 bits but falls to a basic cracking rule in seconds.

```python
tips = [f"Add at least one {name}." for name, present in classes.items() if not present]
```
One tip for every missing character type.

```python
if len(password) < MIN_LENGTH:
    return "Weak", 0, entropy, [f"Use at least {MIN_LENGTH} characters (yours has {len(password)})."] + tips
if password.lower() in common:
    return "Weak", 0, entropy, ["This password appears in a public leaked-password list. Pick a different one."]
```
Two early exits. The order matters: length first because it's the cheapest check. For a leaked password the only tip is "pick another one". Adding a symbol to `password1` doesn't fix it, and the tips shouldn't suggest it does. `.lower()` makes the match case-insensitive, so `Password1` and `PASSWORD1` are both caught.

```python
score = sum(classes.values()) + (len(password) >= 12) + (len(password) >= 16)
```
`sum` of the four booleans counts the character types (0–4). Each length comparison is also a boolean, worth 0 or 1. Maximum score: 6.

```python
if len(password) < 12:
    tips.append("Use 12 or more characters; length adds the most strength.")
label = "Strong" if score >= 5 else "Medium" if score >= 3 else "Weak"
return label, score, entropy, tips
```
A chained conditional expression, read left to right.

## `main()`

```python
common = load_common()
```
The wordlist is loaded once, not once per password.

```python
password = getpass("Password: ")
if not password:
    break
```
`getpass` turns off terminal echo, so the password never appears on screen or in scrollback. An empty line ends the loop. If the terminal can't hide input (some IDE consoles), `getpass` prints a `GetPassWarning` and falls back to visible input. Run it in a real terminal.

```python
del password
```
This only removes the name `password`. The string object stays in memory until Python reuses that memory, and Python strings are immutable, so you can't overwrite them. The README states this as a known limit.

## Attacker's view: how this checker is beaten

The checker blocks **exact** matches from the list. Attackers don't only try the list; they use mangling rules (capitalise the first letter, append a year, add `!`, swap `a` for `@`). Tools like hashcat apply thousands of these rules to every wordlist entry.

Tested against this code:

| Password | Rating | Real strength |
|---|---|---|
| `Password2026!` | **Strong** (5/6) | Dictionary word + year + `!`. Falls to basic rules. |
| `Aaaaaaaaaaa1!` | **Strong** (5/6) | One repeated letter. Trivial. |
| `Summer2026!` | Medium | Season + year, a top pattern in real breaches. |
| `P@ssw0rd!` | Medium | Leetspeak of "password". Not in the 10k list, so it passes the leaked check. |
| 8 spaces | Weak (score 1) | Correctly weak. |

**Lesson:** composition rules (upper + digit + symbol) push people toward predictable patterns and reward them. NIST's password guidance (SP 800-63B) discourages composition rules for this reason and recommends checking against breached-password lists instead. Fixes, roughly in order of payoff:
1. Normalise before the blocklist check: lowercase, undo common leetspeak (`@`→`a`, `0`→`o`), strip trailing digits and symbols, then check the base word.
2. Detect repeats and sequences (`aaaa`, `1234`, `qwerty`).
3. Use a real estimator such as `zxcvbn`, which models these patterns.
4. Check a much larger breach corpus, e.g. the Have I Been Pwned k-anonymity API.

The table above is writeup-worthy: "Two passwords my checker rated Strong, and why composition rules fail."

## Interview questions

**1. Why check against a leaked-password list instead of only enforcing complexity rules?**
Attackers try leaked passwords first because people reuse them. `P@ssword1` satisfies every complexity rule and is still among the first guesses in any wordlist. A blocklist stops the passwords attackers actually try. Complexity rules only change how a password looks.

**2. Your tool says `Password2026!` is 85 bits and Strong. Is it?**
No. The entropy formula assumes random characters. This password is a dictionary word, a capital first letter, a year and `!`, which is the most common mangling pattern. Rule-based cracking finds it almost instantly. The fix is pattern detection or a real estimator such as zxcvbn, not more character-type rules.

**3. You call `del password`. Is the password gone from memory?**
No. `del` removes the variable name. The string object stays in memory until Python reuses that space, and strings are immutable, so they can't be overwritten. A memory dump or core file could still contain it. Handling secrets properly means a mutable buffer (`bytearray`) that you zero after use, or a lower-level language with explicit memory control.

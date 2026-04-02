# Password Strength Checker

A comprehensive password security analyzer that evaluates strength based on length, complexity, entropy, common patterns, and breach databases.

## Features

- **Strength scoring** (0-100) with detailed rating
- **Entropy calculation** (Shannon entropy)
- **Brute-force time estimation** (based on 10B guesses/sec)
- **Pattern detection**: keyboard walks, sequences, repeats, dates, leet speak
- **Common password detection**: checks against top 100 breached passwords
- **Have I Been Pwned integration**: checks if password appeared in data breaches (k-anonymity, your password is never sent over the network)

## Installation

```bash
git clone https://github.com/SebMRX/password-strength-checker.git
cd password-strength-checker
```

No external dependencies — uses only Python standard library.

## Usage

```bash
# Interactive (secure prompt, password hidden)
python password_checker.py

# Direct check
python password_checker.py -p "MyP@ssw0rd!"

# Check against breach database
python password_checker.py -p "test123" --check-breach
```

## Example Output

```
=======================================================
  PASSWORD STRENGTH ANALYSIS
=======================================================

  Score   : ████████████████░░░░ 80/100 (STRONG)

  Length       : 14 characters
  Charset size : 94 characters
  Entropy      : 3.45 bits/char
  Crack time   : 2.1 million years (10B guesses/sec)
  [+] Not found in known data breaches

  Findings:
    [-] Contains a year — avoid dates in passwords

  Suggestions:
    → Mix uppercase, lowercase, numbers, and symbols

=======================================================
```

## How Scoring Works

| Category | Max Points | Criteria |
|----------|-----------|----------|
| Length | 30 | 16+ chars = 30pts, 12+ = 25pts, 10+ = 20pts |
| Diversity | 25 | Each character type adds 6pts |
| Entropy | 20 | Higher entropy = more points |
| Bonus | 25 | Long + diverse passwords |
| Penalties | -30 | Common passwords, patterns, sequences |

## Disclaimer

This tool is for **educational purposes**. Never share your real passwords with untrusted tools. The HIBP check uses k-anonymity — your full password hash is never transmitted.

## License

MIT License

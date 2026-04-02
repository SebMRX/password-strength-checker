#!/usr/bin/env python3
"""
Password Strength Checker - Analyze password security with detailed feedback.

Evaluates passwords based on length, complexity, entropy, common patterns,
and checks against a list of known breached passwords.

Usage:
    python password_checker.py
    python password_checker.py -p "mypassword"
    python password_checker.py --check-breach

Author: SebMRX
"""

import re
import math
import string
import hashlib
import argparse
import getpass
from collections import Counter


# Top 100 most common passwords
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212",
    "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "2000", "charlie", "robert", "thomas", "hockey", "ranger",
    "daniel", "starwars", "klaster", "112233", "george", "computer",
    "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass", "maggie",
    "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese",
    "amanda", "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas",
    "austin", "thunder", "taylor", "matrix", "admin", "password1",
    "welcome", "hello", "passw0rd", "p@ssword", "qwerty123",
}

# Common keyboard patterns
KEYBOARD_PATTERNS = [
    "qwerty", "qwertz", "azerty", "asdf", "zxcv", "wasd",
    "1234", "2345", "3456", "4567", "5678", "6789", "7890",
    "0987", "9876", "8765", "7654", "6543", "5432", "4321",
    "abcd", "bcde", "cdef", "defg", "efgh", "fghi",
]

# Leet speak substitutions
LEET_MAP = {"@": "a", "3": "e", "1": "i", "0": "o", "5": "s", "$": "s", "7": "t"}


def calculate_entropy(password):
    """Calculate Shannon entropy of the password."""
    if not password:
        return 0.0

    freq = Counter(password)
    length = len(password)
    entropy = -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )
    return round(entropy, 2)


def calculate_charset_size(password):
    """Determine the character set size used in the password."""
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        charset += 32
    return charset


def estimate_crack_time(password):
    """Estimate time to brute-force the password (assuming 10B guesses/sec)."""
    charset = calculate_charset_size(password)
    if charset == 0:
        return "instant"

    combinations = charset ** len(password)
    guesses_per_second = 10_000_000_000  # 10 billion (modern GPU cluster)
    seconds = combinations / guesses_per_second

    if seconds < 1:
        return "instant"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} days"
    elif seconds < 86400 * 365 * 1000:
        return f"{seconds / (86400 * 365):.1f} years"
    elif seconds < 86400 * 365 * 1e6:
        return f"{seconds / (86400 * 365 * 1000):.1f} thousand years"
    elif seconds < 86400 * 365 * 1e9:
        return f"{seconds / (86400 * 365 * 1e6):.1f} million years"
    else:
        return f"{seconds / (86400 * 365 * 1e9):.1f} billion years"


def deleet(password):
    """Convert leet speak back to plain text for pattern matching."""
    result = password.lower()
    for leet, char in LEET_MAP.items():
        result = result.replace(leet, char)
    return result


def analyze_password(password):
    """
    Perform comprehensive password strength analysis.

    Returns:
        dict with score (0-100), rating, and detailed findings.
    """
    findings = []
    score = 0
    length = len(password)

    # --- Length scoring (max 30 points) ---
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 10:
        score += 20
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 8
    else:
        findings.append(f"[!] Too short ({length} chars) — use at least 12 characters")

    # --- Character diversity (max 25 points) ---
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    diversity = sum([has_lower, has_upper, has_digit, has_special])
    score += diversity * 6

    if not has_upper:
        findings.append("[-] Missing uppercase letters")
    if not has_lower:
        findings.append("[-] Missing lowercase letters")
    if not has_digit:
        findings.append("[-] Missing numbers")
    if not has_special:
        findings.append("[-] Missing special characters (!@#$%^&*)")

    # --- Entropy scoring (max 20 points) ---
    entropy = calculate_entropy(password)
    if entropy >= 4.0:
        score += 20
    elif entropy >= 3.0:
        score += 15
    elif entropy >= 2.0:
        score += 10
    elif entropy >= 1.0:
        score += 5
    else:
        findings.append("[!] Very low entropy — characters are too repetitive")

    # --- Pattern checks (penalties) ---

    # Common password check
    lower_pw = password.lower()
    deleet_pw = deleet(password)
    if lower_pw in COMMON_PASSWORDS or deleet_pw in COMMON_PASSWORDS:
        score -= 30
        findings.append("[!] CRITICAL: This is a commonly breached password!")

    # Keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower_pw:
            score -= 10
            findings.append(f"[!] Contains keyboard pattern: '{pattern}'")
            break

    # Repeated characters (e.g., "aaa", "111")
    if re.search(r"(.)\1{2,}", password):
        score -= 10
        findings.append("[!] Contains repeated characters (e.g., 'aaa')")

    # Sequential characters
    sequential = 0
    for i in range(len(password) - 1):
        if ord(password[i]) + 1 == ord(password[i + 1]):
            sequential += 1
    if sequential >= 3:
        score -= 10
        findings.append("[!] Contains sequential characters (e.g., 'abcd', '1234')")

    # All same case or all digits
    if password.isdigit():
        score -= 15
        findings.append("[!] Password is all numbers")
    elif password.isalpha() and (password.islower() or password.isupper()):
        score -= 10
        findings.append("[!] Password is all same-case letters")

    # Date-like patterns
    if re.search(r"(19|20)\d{2}", password):
        score -= 5
        findings.append("[-] Contains a year — avoid dates in passwords")

    # --- Bonus points (max 25) ---
    if length >= 12 and diversity >= 3:
        score += 10
    if length >= 16 and diversity == 4:
        score += 15

    # Clamp score
    score = max(0, min(100, score))

    # Rating
    if score >= 80:
        rating = "STRONG"
        color = "\033[92m"  # green
    elif score >= 60:
        rating = "MODERATE"
        color = "\033[93m"  # yellow
    elif score >= 40:
        rating = "WEAK"
        color = "\033[91m"  # red
    else:
        rating = "VERY WEAK"
        color = "\033[91m"

    return {
        "score": score,
        "rating": rating,
        "color": color,
        "entropy": entropy,
        "charset_size": calculate_charset_size(password),
        "crack_time": estimate_crack_time(password),
        "findings": findings,
        "length": length,
        "diversity": diversity,
    }


def check_hibp(password):
    """
    Check if password appears in Have I Been Pwned database.
    Uses k-anonymity model (only sends first 5 chars of SHA-1 hash).
    """
    try:
        import urllib.request

        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordChecker"})
        response = urllib.request.urlopen(req, timeout=5)
        body = response.read().decode("utf-8")

        for line in body.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)

        return 0
    except Exception:
        return -1  # Could not check


def display_results(result, breach_count=None):
    """Display formatted analysis results."""
    reset = "\033[0m"
    bold = "\033[1m"
    color = result["color"]

    print()
    print("=" * 55)
    print(f"  PASSWORD STRENGTH ANALYSIS")
    print("=" * 55)
    print()

    # Score bar
    filled = result["score"] // 5
    bar = "█" * filled + "░" * (20 - filled)
    print(f"  Score   : {color}{bar} {result['score']}/100 ({result['rating']}){reset}")
    print()

    # Stats
    print(f"  Length       : {result['length']} characters")
    print(f"  Charset size : {result['charset_size']} characters")
    print(f"  Entropy      : {result['entropy']} bits/char")
    print(f"  Crack time   : {result['crack_time']} (10B guesses/sec)")

    if breach_count is not None:
        if breach_count > 0:
            print(f"  \033[91m[!] BREACHED: Found {breach_count:,} times in data breaches!{reset}")
        elif breach_count == 0:
            print(f"  \033[92m[+] Not found in known data breaches{reset}")
        else:
            print(f"  [?] Could not check breach database")

    # Findings
    if result["findings"]:
        print()
        print("  Findings:")
        for finding in result["findings"]:
            print(f"    {finding}")

    # Suggestions
    print()
    print("  Suggestions:")
    if result["length"] < 12:
        print("    → Use at least 12 characters")
    if result["diversity"] < 4:
        print("    → Mix uppercase, lowercase, numbers, and symbols")
    if result["score"] < 60:
        print("    → Consider using a passphrase (e.g., 'correct-horse-battery-staple')")
        print("    → Use a password manager to generate strong passwords")

    print()
    print("=" * 55)


def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Checker - Analyze password security",
    )
    parser.add_argument("-p", "--password", help="Password to check (omit for secure prompt)")
    parser.add_argument(
        "--check-breach",
        action="store_true",
        help="Check against Have I Been Pwned database",
    )

    args = parser.parse_args()

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter password to check: ")

    if not password:
        print("[!] No password provided.")
        return

    result = analyze_password(password)

    breach_count = None
    if args.check_breach:
        print("[*] Checking Have I Been Pwned database...")
        breach_count = check_hibp(password)

    display_results(result, breach_count)


if __name__ == "__main__":
    main()

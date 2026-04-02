# Password Strength Checker

checks how strong your password is. gives a score out of 100 and tells you whats wrong with it

## what it checks

- length, uppercase/lowercase, numbers, special chars
- entropy calculation
- common passwords list (top 100 breached ones)
- keyboard patterns like qwerty, 1234 etc
- leet speak detection (p@ssw0rd -> password)
- estimates brute force crack time
- can check haveibeenpwned database (optional)

## usage

```
python password_checker.py
python password_checker.py -p "mypassword"
python password_checker.py -p "test123" --check-breach
```

the hibp check uses k-anonymity so your password never gets sent over the network

no external dependencies needed

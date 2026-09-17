import re
import math
import getpass
import colorama as color  # bytter farge på output tekst

color.init(autoreset=True)

def calculate_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32
    if charset == 0:
        return 0
    return len(password) * math.log2(charset)

def check_password(password):
    score = 0.0
    suggestions = []

    # Length (maks 4 poeng)
    if len(password) >= 12:
        score += 4
    elif len(password) >= 8:
        score += 2
        suggestions.append("Bruk minst 12 tegn.")
    else:
        suggestions.append("Bruk minst 12 tegn.")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1.5
    else:
        suggestions.append("Legg til små bokstaver.")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1.5
    else:
        suggestions.append("Legg til store bokstaver.")

    # Numbers
    if re.search(r"[0-9]", password):
        score += 1.5
    else:
        suggestions.append("Legg til tall.")

    # Special characters
    if re.search(r"[^a-zA-Z0-9]", password):
        score += 1.5
    else:
        suggestions.append("Legg til spesialtegn.")

    # Common weak patterns
    weak_patterns = [
        # Vanlige passord
        "password", "password1", "password123", "passw0rd", "p@ssword",
        "qwerty", "qwerty123", "letmein", "welcome", "welcome123",
        "admin", "admin123", "administrator", "root", "login",
        "secret", "master", "changeme",
        # Tallsekvenser
        "123456", "1234567", "12345678", "123456789", "1234567890",
        "111111", "11111111", "000000", "00000000", "123123", "321321",
        # Tastaturmønstre
        "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "qazwsx",
        "1q2w3e", "1q2w3e4r",
        # Vanlige fraser
        "iloveyou", "iloveyou123", "trustno1", "football", "baseball",
        "monkey", "dragon", "sunshine", "princess", "shadow",
        "superman", "freedom", "whatever",
        # Norske vanlige passord
        "passord", "passord123", "velkommen", "velkommen123",
        "norge", "norge123", "oslo", "oslo123",
        "sommer", "sommer123", "vinter", "vinter123"
    ]

    if password.lower() in weak_patterns:
        score = min(score, 2)
        suggestions.append("Dette passordet er for vanlig. Velg et nytt og unikt passord.")

    entropy = calculate_entropy(password)

    # Classification (tilpasset 0–10)
    if score < 3:
        strength = "Very Weak"
    elif score < 5:
        strength = "Weak"
    elif score < 7:
        strength = "Moderate"
    elif score < 9:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return score, strength, entropy, suggestions

def main():
    print("Password Strength Checker")
    password = getpass.getpass(color.Fore.YELLOW + "\nSkriv inn passordet: ")
    score, strength, entropy, suggestions = check_password(password)

    print(color.Fore.CYAN + "\nResultat")
    print("-------------------------")
    print(f"Score:    {score:.1f}/10")
    print(f"Strength: {strength}")
    print(f"Entropy:  {entropy:.2f} bits")

    if suggestions:
        print("\nForslag til forbedring:")
        for suggestion in suggestions:
            print(f"- {suggestion}")
    else:
        print("\nPassordet oppfyller alle grunnleggende krav.")


main()

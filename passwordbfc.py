import hashlib
import requests
import itertools
import string
import time

def hash_password(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1[:5], sha1[5:]

def check_password_in_rockyou(password):
    hash_prefix, hash_suffix = hash_password(password)
    url = f'https://api.pwnedpasswords.com/range/{hash_prefix}'
    response = requests.get(url)
    
    if response.status_code == 200:
        hashes = response.text.splitlines()
        for h in hashes:
            h_prefix, count = h.split(':')
            if h_prefix == hash_suffix:
                return True, count
    return False, None

def estimate_crack_time(password):
    chars_lower = string.ascii_lowercase
    chars_upper = string.ascii_uppercase
    chars_digits = string.digits
    chars_special = string.punctuation

    char_space = 0
    count_lowercase = sum(1 for c in password if c.islower())
    count_uppercase = sum(1 for c in password if c.isupper())
    count_digits = sum(1 for c in password if c.isdigit())
    count_special = len(password) - count_lowercase - count_uppercase - count_digits

    if count_lowercase > 0:
        char_space += len(chars_lower)
    if count_uppercase > 0:
        char_space += len(chars_upper)
    if count_digits > 0:
        char_space += len(chars_digits)
    if count_special > 0:
        char_space += len(chars_special)

    total_possible_passwords = char_space ** len(password)
    attempts_per_second = 1_000_000
    estimated_time_seconds = total_possible_passwords / attempts_per_second
    days, rem = divmod(estimated_time_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)

    print(f"Password is {len(password)} characters long and contains:")
    print(f" - Lowercase letters: {count_lowercase}")
    print(f" - Uppercase letters: {count_uppercase}")
    print(f" - Digits: {count_digits}")
    print(f" - Special characters: {count_special}")
    print(f"Total possible passwords: {total_possible_passwords:,}")
    print(f"Estimated time to crack the password: {int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds")

def crack_password(password):
    found, count = check_password_in_rockyou(password)
    if found:
        print(f"Password '{password}' found in a common password list ({count} occurrences).")
        return 0, password

    chars = string.ascii_letters + string.digits + string.punctuation
    attempts = 0
    estimate_crack_time(password)  # Call the estimate function to display the password details and cracking time estimate

    for length in range(1, 9):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guess = ''.join(guess)
            print(guess, end='\r')
            if guess == password:
                print(guess)
                return attempts, guess

def main():
    password = input("Enter the password you want to check: ")
    start_time = time.time()
    attempts, cracked_password = crack_password(password)
    end_time = time.time()
    print(f"Password '{cracked_password}' cracked in {attempts} attempts and {end_time - start_time:.2f} seconds")

if __name__ == '__main__':
    main()

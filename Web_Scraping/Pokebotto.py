from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOption
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.options import Options as FirefoxOption
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
import time
import random
import requests
# from os import system
import json
from bs4 import BeautifulSoup
from fp.fp import FreeProxy

# Country that being blocked
ban_lst = ['US', 'RU', 'NL', 'GB', 'HK']

prox_list = ['124.108.6.20:8085', '103.118.44.142:8080', '185.36.145.215:80']

# User Agents list for random selection
user_agents_firefox = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.6; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Mozilla/5.0 (X11; Linux i686; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0"
]

# Source: https://github.com/ShadowHackrs/Auto-Gmail-Creator/blob/main/auto_gmail_creator.py
user_agents_chrome = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.52",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 YaBrowser/21.8.1.468 Yowser/2.5 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0",
    "Mozilla/5.0 (X11; CrOS x86_64 14440.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4807.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14467.0.2022) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4838.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14469.7.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.13 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14455.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4827.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14469.11.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.17 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14436.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4803.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14475.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4840.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14469.3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.9 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14471.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4840.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14388.37.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.9 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14409.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4829.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14395.0.2021) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4765.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14469.8.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.14 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14484.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4840.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14450.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4817.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14473.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4840.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14324.72.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.91 Safari/537.36",       # OK
    "Mozilla/5.0 (X11; CrOS x86_64 14454.0.2022) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4824.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14453.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4816.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14447.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4815.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14477.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4840.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14476.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4840.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14469.8.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.9 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14588.67.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14588.67.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14526.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.82 Safari/537.36",      # OK
    "Mozilla/5.0 (X11; CrOS x86_64 14695.25.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.22 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14526.89.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.91 Safari/537.36",      # OK
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
]

browser_lst = ['firefox']
file_usrlst = 'Poke/DangTienDung1309.txt'

def create_firefox(prx_ip, prx_port, check_https):
    # Choose random user-agent
    rduagent = random.choice(user_agents_firefox + user_agents_chrome)
    print(f'[+] User-agent: {rduagent}')

    ffp = FirefoxProfile()
    ffp.set_preference("general.useragent.override", rduagent)
    # ffp.set_preference("browser.privatebrowsing.autostart", True)
    
    ffo = FirefoxOption()
    ffo.profile = ffp
    # ffo.add_argument('-private')

    # about:config
    ## HTTP Proxy
    if(check_https == False):
        print('[+] Setting HTTP Proxy config...')
        ffo.set_preference("network.proxy.http", prx_ip)
        ffo.set_preference("network.proxy.http_port", int(prx_port))

    ## HTTPS Proxy
    else:
        print('[+] Setting HTTPS Proxy config...')
        ffo.set_preference("network.proxy.ssl", prx_ip)
        ffo.set_preference("network.proxy.ssl_port", int(prx_port))

    ffo.set_preference("network.proxy.type", 1)

    driver = webdriver.Firefox(options=ffo)
    action = ActionChains(driver)
    return driver, action

def create_chrome(ip, port):
    PROXY = ip + ':' + port
    print('[+] Proxy of Chrome: ', PROXY)
    # webdriver.DesiredCapabilities.CHROME['proxy'] = {
    #     "httpProxy": PROXY,
    #     # "ftpProxy": PROXY,
    #     # "sslProxy": PROXY,
    #     "proxyType": 'MANUAL',
    # }

    # webdriver.DesiredCapabilities.CHROME['acceptSslCerts']=True
    # print('[+] Print setting: ', webdriver.DesiredCapabilities.CHROME)

    uagent_chr = random.choice(user_agents_chrome)
    print(f'[+] User-agent: {uagent_chr}')

    chop = ChromeOption()
    # chop.add_argument('--headless')
    # chop.add_argument('--no-sandbox')
    chop.add_argument(f'--user-agent={uagent_chr}')
    chop.add_argument(f'--proxy-server=http://{ip}:{port}')

    driver = webdriver.Chrome(options=chop, service=ChromeService(executable_path='ChromeDriver/chromedriver.exe'))
    action = ActionChains(driver)
    return driver, action

def get_working_proxy():
    req = requests.get('https://free-proxy-list.net/en/')
    print('[!] Finding proxy...')

    req_soup = BeautifulSoup(req.text, 'html.parser').find('tbody').find_all('tr')
    rand_ele = random.choice(req_soup).find_all('td')
    print('[+] Found proxy!')

    # print('[!!!] Debug:', req_soup[0:10])
    ele_txt = ''
    check_ssl = False

    for ele in range(0, len(rand_ele)):
        ele_txt += rand_ele[ele].text + '|'

    ip = (ele_txt.split('|'))[0]
    port = (ele_txt.split('|'))[1]
    country_id = (ele_txt.split('|'))[2]
    country = (ele_txt.split('|'))[3]
    https = (ele_txt.split('|'))[6].lower()

    if(check_ssl == 'yes'):
        check_ssl = True

    print(f'[+] Country: {country}')
    print(f'[+] HTTPS: {https}')
    return ip, port, country_id, check_ssl

def get_working_fp():
    proxy = FreeProxy(rand=True, timeout=1).get()
    print(f'\n\n[+] Getting working proxy: {proxy}')

    text = proxy.split(':')
    ip = text[1][2:]
    port = text[2]
    print(f'[+] IP: {ip}')
    print(f'[+] Port: {port}')
    return ip, port

def inputBox(action:ActionChains, inpTxt, input):
    # Click and enter the input to the textbox
    action.click(on_element=inpTxt)
    action.send_keys(input)

    # Perform action
    action.perform()

def changePasswd(action:ActionChains, passwd, cf_passwd, input, btn):
    # Enter new pass
    inputBox(action, passwd, input)

    # Enter for confirmation
    inputBox(action, cf_passwd, input)

    # Click button
    btn.click()

def find_ele(driver, box):
    # Find element to input
    if(driver.find_element(By.XPATH, box)):
        found_box = driver.find_element(By.XPATH, box)
    else:
        found_box = None
    return found_box

def loginForm(action, box, button, input):
    # Click and send message to the box
    inputBox(action, box, input)
    
    # Found and click button
    button.click()

def create_pokesen(driver, action, yr_email, btn_login_xpath, box_regacc_xpath, btn_regacc_xpath, btn_cf_regacc_xpath):
    print('##### Create Pokesen account!!! ####')
    # driver.switch_to.new_window('tab')
    driver.get('https://www.pokemoncenter-online.com/')
    time.sleep(5)

    # Find log-in button
    btn_login = find_ele(driver, btn_login_xpath)
    btn_login.click()
    time.sleep(1)
    
    # Reload the page
    driver.refresh()
    print('[!] Refreshing page...')
    time.sleep(1)

    # Find the textbox and button for registering account
    box_regacc = find_ele(driver, box_regacc_xpath)
    btn_regacc = find_ele(driver, btn_regacc_xpath)
    # time.sleep(1)
    inputBox(action, box_regacc, yr_email)
    btn_regacc.click()
    
    time.sleep(4)
    
    # For E-mail confirmation
    #if(find_ele(driver, btn_cf_regacc_xpath)):
    btn_cf_regacc = find_ele(driver, btn_cf_regacc_xpath)

    btn_cf_regacc.click()
    print('[+] Create pokesen account successfully!\n\n\n')
    time.sleep(3)

num_user = 1
try:  
    with open(file_usrlst, 'r') as f:
        for line in f:
            if(line == '' or line == '\n'):
                print('[+] Done!...')
                break
            
            prx_ip, prx_port, country, check_https = get_working_proxy()
            print(f'[+] IP: {prx_ip}')
            print(f'[+] Port: {prx_port}')

            # If is easy banned country
            # while(country in ban_lst):
            #     print(f'[!] Uh oh. Usually {country} Proxies is always blocked. Trying to find again...\n')
            prx_ip, prx_port, country, check_https = get_working_proxy()

            driver, action = create_firefox(prx_ip, prx_port, check_https)
            print('[+] Loop:', num_user)

            # Number of current user for logging
            txt = line.split('|')
            yr_email = txt[0]
            print('[+] Email:', yr_email)
            btn_login_xpath = "//a[contains(text(),'ログイン ／ 会員登録')]"
            box_regacc_xpath = "//input[@id='login-form-regist-email']"
            btn_regacc_xpath = "//button[@id='form2Button']"
            btn_cf_regacc_xpath = "//a[@id='send-confirmation-email']"
            
            # Create Pokesen account
            create_pokesen(driver, action, yr_email, btn_login_xpath, box_regacc_xpath, btn_regacc_xpath, btn_cf_regacc_xpath)

            driver.quit()
            # break

except Exception as e:
    print(f'[-] Error: {e}')
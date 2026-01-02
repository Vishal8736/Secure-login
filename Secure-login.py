import time
import json
import os
import base64
import sys
from getpass import getpass
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from colorama import Fore, Style, init

# Encryption Libraries
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

init(autoreset=True)

# Encrypted File Name
ENCRYPTED_FILE = "secure_data.bin"

def generate_key(master_password):
    """Master password se encryption key banata hai"""
    salt = b'vishal_subhi_salt_88' # Fixed salt for consistency
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.GREEN + Style.BRIGHT + """
    ###########################################
    #       VISHAL ❤️  SUBHI - SECURE LOGIN    #
    #       [ ENCRYPTED & OBFUSCATED ]        #
    ###########################################
    """ + Style.RESET_ALL)

# Site Configurations
SITES = [
    {
        "name": "Bugcrowd",
        "url": "https://identity.bugcrowd.com/login?user_hint=researcher&returnTo=https%3A%2F%2Fbugcrowd.com%2Fdashboard",
        "email_selector": (By.NAME, "email"),
        "password_selector": (By.NAME, "password"),
        "submit_selector": (By.CSS_SELECTOR, "button[type='submit']"),
        "otp_selector": (By.NAME, "code"),
        "needs_otp": True
    },
    {
        "name": "GitHub",
        "url": "https://github.com/login",
        "email_selector": (By.ID, "login_field"),
        "password_selector": (By.ID, "password"),
        "submit_selector": (By.NAME, "commit"),
        "otp_selector": (By.ID, "app_totp"),
        "needs_otp": True
    },
    {
        "name": "HackerOne",
        "url": "https://hackerone.com/users/sign_in",
        "email_selector": (By.ID, "user_email"),
        "password_selector": (By.ID, "user_password"),
        "submit_selector": (By.NAME, "commit"),
        "otp_selector": (By.ID, "two_factor_code"),
        "needs_otp": True
    }
]

def load_creds(fernet):
    if os.path.exists(ENCRYPTED_FILE):
        try:
            with open(ENCRYPTED_FILE, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception:
            print(Fore.RED + "\n[!] WRONG MASTER PASSWORD OR CORRUPT FILE!")
            sys.exit(1)
    else:
        return None

def setup_new_creds(fernet):
    print(Fore.CYAN + "\n[*] First Run Setup: Saving Credentials securely...")
    creds = {}
    
    # Bugcrowd
    print(Fore.YELLOW + "--- Bugcrowd ---")
    creds['Bugcrowd'] = {
        'email': input("Email: "),
        'password': getpass("Password: ")
    }
    
    # GitHub
    print(Fore.YELLOW + "--- GitHub ---")
    creds['GitHub'] = {
        'email': input("Email: "),
        'password': getpass("Password: ")
    }
    
    # HackerOne
    print(Fore.YELLOW + "--- HackerOne ---")
    creds['HackerOne'] = {
        'email': input("Email: "),
        'password': getpass("Password: ")
    }
    
    data = json.dumps(creds).encode()
    encrypted_data = fernet.encrypt(data)
    
    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(encrypted_data)
    
    print(Fore.GREEN + "[+] Credentials Encrypted & Saved!")
    return creds

def login_process(driver, site_config, creds):
    site_name = site_config['name']
    print(Fore.CYAN + f"[*] Accessing {site_name}...")
    
    try:
        driver.get(site_config['url'])
        wait = WebDriverWait(driver, 30)
        
        try:
            email_field = wait.until(EC.element_to_be_clickable(site_config['email_selector']))
            email_field.clear()
            email_field.send_keys(creds[site_name]['email'])
        except:
            pass 

        try:
            pass_field = driver.find_element(*site_config['password_selector'])
            pass_field.send_keys(creds[site_name]['password'])
            driver.find_element(*site_config['submit_selector']).click()
        except:
             pass

        if site_config['needs_otp']:
            print(Fore.MAGENTA + f"[OTP] Check Authenticator for {site_name}")
            otp = input(Fore.MAGENTA + f"Enter OTP for {site_name}: ")
            if otp:
                try:
                    otp_field = wait.until(EC.element_to_be_clickable(site_config['otp_selector']))
                    otp_field.send_keys(otp)
                    otp_field.submit()
                except:
                    pass
        print(Fore.GREEN + f"[✓] {site_name} Done.\n")

    except Exception as e:
        print(Fore.RED + f"[X] Error on {site_name}: {e}")

def main():
    print_banner()
    
    # SECURITY CHECK
    mp = getpass(Fore.YELLOW + "ENTER MASTER PASSWORD TO UNLOCK TOOL: ")
    key = generate_key(mp)
    fernet = Fernet(key)
    
    creds = load_creds(fernet)
    if not creds:
        creds = setup_new_creds(fernet)
    
    print(Fore.GREEN + "[+] Access Granted. Launching Browser...")
    
    options = uc.ChromeOptions()
    driver = uc.Chrome(options=options, use_subprocess=True)
    
    login_process(driver, SITES[0], creds)
    
    for site in SITES[1:]:
        driver.execute_script("window.open('');")
        driver.switch_to.window(driver.window_handles[-1])
        login_process(driver, site, creds)
    
    print(Fore.GREEN + "\nAll systems operational.")
    input("Press Enter to Exit...")

if __name__ == "__main__":
    main()

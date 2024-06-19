import math
from collections import Counter
import textwrap
import google.generativeai as genai
import netifaces
from scapy.all import ARP, Ether, srp
import subprocess
import platform
import re
import requests
import ipaddress
import netifaces
from scapy.all import ARP, Ether, srp

def get_wifi_name():
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, check=True)
        lines = result.stdout.split('\n')
        for line in lines:
            if "SSID" in line:
                ssid = line.split(":")[1].strip()
                return ssid
    except subprocess.CalledProcessError as e:
        print("Error:", e)
        return None

def get_wifi_signal_strength():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
        signal_strength_line = re.search(r'^\s*Signal\s+:\s+(\d+)%', result.stdout, re.MULTILINE)
        if signal_strength_line:
            signal_strength = signal_strength_line.group(1).strip()
            return f"{signal_strength}%"
        else:
            return "Signal Strength not found"
    except Exception as e:
        print(f"Error: {e}")
        return None


def get_network_range(interface):
    # Get the IPv4 address and subnet mask of the specified interface
    try:
        addr_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip_address = addr_info['addr']
        subnet_mask = addr_info['netmask']
    except KeyError:
        print(f"Error: Unable to retrieve IPv4 address and subnet mask for interface '{interface}'.")
        return None

    # Calculate the network address and prefix length
    network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
    network_range = f"{network.network_address}/{network.prefixlen}"
    return network_range

def scan_network(ip_range):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(arp_request, timeout=3, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def check_guest_network_isolation(interface="Wi-Fi"):
    # Detect the network range automatically from the default interface
    default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    ip_range = get_network_range(default_interface)
    
    if ip_range:
        print(f"Detected network range: {ip_range}")
        devices = scan_network(ip_range)
        
        print("Devices connected to the network:")
        print("IP Address\t\tMAC Address")
        print("------------------------------------")
        count_device = 0
        for device in devices:
            count_device += 1
            print(f"{device['ip']}\t{device['mac']}")
    if count_device > 0:
        return 0
    else:
        return 10


def truncate_authentication(authentication):
    if 'WPA3-Personal' in authentication:
        return 'WPA3-Personal'
    elif 'WPA2-Enterprise' in authentication:
        return 'WPA2-Enterprise'
    elif 'WPA2-Personal' in authentication:
        return 'WPA2-Personal'
    elif 'WPA' in authentication:
        return 'WPA'
    elif 'WEP' in authentication:
        return 'WEP'
    return authentication.split()[0]


def truncate_cipher(cipher):
    if 'CCMP' in cipher:
        return 'AES-CCMP'
    elif 'GCMP' in cipher:
        return 'AES-GCMP'
    elif 'TKIP' in cipher:
        return 'TKIP'
    elif 'WEP' in cipher:
        return 'WEP'
    return cipher

def get_wifi_standard():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
        wifi_info = result.stdout
        radio_type_line = re.search(r'^\s*Radio\s+type\s+:\s+(.+)$', wifi_info, re.MULTILINE)
        if radio_type_line:
            radio_type = radio_type_line.group(1).strip()
            if "802.11be" in radio_type:
                return "Wi-Fi 7 (802.11be)"
            elif "802.11ax" in radio_type:
                return "Wi-Fi 6 (802.11ax)"
            elif "802.11ac" in radio_type:
                return "Wi-Fi 5 (802.11ac)"
            elif "802.11n" in radio_type:
                return "Wi-Fi 4 (802.11n)"
            elif "802.11g" in radio_type:
                return "Wi-Fi 3 (802.11g)"
            elif "802.11a" in radio_type:
                return "Wi-Fi 2 (802.11a)"
            elif "802.11b" in radio_type:
                return "Wi-Fi 1 (802.11b)"
            else:
                return "Unknown"
        else:
            return "Not found"
    except Exception as e:
        print(f"Error: {e}")
        return None

def get_connected_wifi_info():
    system_platform = platform.system()
    if system_platform == 'Windows':
        try:
            result = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'])
            # Try decoding with utf-8, ignore errors
            interface_info = result.decode('utf-8', errors='ignore')
            connected_interface_start = interface_info.find("State                  : connected")
            if connected_interface_start != -1:
                connected_interface_info = interface_info[connected_interface_start:]
                # Try decoding with utf-8, ignore errors
                try:
                    security_info = subprocess.check_output(['netsh', 'wlan', 'show', 'interface']).decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    # Try decoding with a different encoding
                    security_info = subprocess.check_output(['netsh', 'wlan', 'show', 'interface']).decode('latin-1', errors='ignore')
                authentication = None
                cipher = None
                lines = security_info.split('\n')
                for line in lines:
                    if line.strip().startswith("Authentication"):
                        authentication = line.split(':', 1)[1].strip()
                    elif line.strip().startswith("Cipher"):
                        cipher = line.split(':', 1)[1].strip()
                return authentication, cipher
            else:
                print("No connected Wi-Fi interface found.")
        except subprocess.CalledProcessError as e:
            print(f"Error fetching Wi-Fi information: {e}")
    else:
        print("Unsupported operating system.")


def get_security_score():
    
    authentication, cipher = get_connected_wifi_info()
    authentication = truncate_authentication(authentication)
    cipher = truncate_cipher(cipher)
    
    authentication_scores = {'WEP': 1, 'WPA': 3, 'WPA2-Personal': 5, 'WPA2-Enterprise': 7, 'WPA3-Personal': 9, 'WPA3-Enterprise': 10}
    cipher_scores = {'WEP': 1, 'TKIP': 4, 'AES-CCMP': 7, 'AES-GCMP': 10}
    standard_scores = {'Wi-Fi 1 (802.11b)': 1, 'Wi-Fi 2 (802.11a)': 3, 'Wi-Fi 3 (802.11g)': 5, 'Wi-Fi 4 (802.11n)': 7,
                       'Wi-Fi 5 (802.11ac)': 8, 'Wi-Fi 6 (802.11ax)': 9, 'Wi-Fi 7 (802.11be)': 10 }
    
    authentication_score = authentication_scores.get(authentication, 0)
    
    cipher_score = cipher_scores.get(cipher, 0)
    
    wifi_standard = get_wifi_standard()
    standard_score = standard_scores.get(wifi_standard, 0)
    
    if authentication_score == 0 or cipher_score == 0:
        return 0
    security_score = (authentication_score*5 + cipher_score*4 + standard_score) / 10
    return security_score


def calculate_entropy(word):
    freq_dict = Counter(word)
    total_chars = len(word)
    probabilities = {char: freq / total_chars for char, freq in freq_dict.items()}

    entropy = abs(-sum(prob * math.log2(prob) for prob in probabilities.values()))
    print("Entropy of the Wi-Fi Password: ", entropy)
    
    # Calculate entropy score
    entropy_score = round(((entropy - 0) / (5.977 - 0)) * 5, 1)
    print("Entropy Score: ", entropy_score)
    
    return entropy_score


def check_dict_strength(word):
    dict_score = 0
    with open("common_passwords.txt", "r") as f:
        common_passwords = [line.strip() for line in f]
    if len(word)>0 and word.lower() not in common_passwords:
        dict_score = 2
        print("Dictionary Score: ", dict_score)
        return dict_score
    print("Dictionary Score: ", dict_score)
    return dict_score


def genai_response(password):
    GOOGLE_API_KEY = "AIzaSyCIAl3yAA0rZL-nMRDr1sFScZvEkBoYlt0"
    genai.configure(api_key=GOOGLE_API_KEY)
    model = genai.GenerativeModel('gemini-pro')
    prompt_text = "Given the input " + password + ", identify if any name is present in the begining or in the end. If a meaningful name is found, indicate its presence in the input as only 'Yes' otherwise only 'No'."
    response = model.generate_content(prompt_text).text
    # if(len(password)>0):
    #     print("The Password Contains Name: ", response)
    ai_score = 0
    if "no" in response.lower() and len(password)>0:
        ai_score = 3
    print("AI Score: ", ai_score)
    return ai_score

def get_password_score(password):

    ai_score = genai_response(password)
    entropy_score = calculate_entropy(password)
    dict_score = check_dict_strength(password)
    password_score = ai_score + entropy_score + dict_score
    return password_score

def print_progress_bar(progress):
    bar_length = 50
    progress_length = int(bar_length * progress / 100)
    remaining_length = bar_length - progress_length
    progress_bar = '[' + '*' * progress_length + '-' * remaining_length + ']'
    print(f'\r{progress_bar} => {progress}%', end='', flush=True)

def get_firewall_score():
    filename = "url_list_1.txt"
    firewall_score = 0
    try:
        with open(filename, 'r') as file:
            urls = file.readlines()
            total_urls = len(urls)
            failed_count = 0
            timeout_count = 0

            for i, url in enumerate(urls, start=1):
                url = url.strip()  # Remove leading/trailing whitespace
                try:
                    response = requests.get("http://" + url, timeout=0.5)  # Timeout set to 0.5 seconds (500 milliseconds)
                    if response.status_code == 403:
                        failed_count += 1
                        # print(f"Failed to fetch URL: {url} (Status code: {response.status_code})")
                except requests.exceptions.RequestException as e:
                    timeout_count += 1
                    # print(f"Failed to fetch URL: {url} (Error: {e})")
                
                progress = (i * 100) // total_urls
                print_progress_bar(progress)

            failed_rate = (failed_count * 100) / (total_urls - timeout_count)
            if (failed_rate >= 10):
                firewall_score += 10

    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    
    return firewall_score

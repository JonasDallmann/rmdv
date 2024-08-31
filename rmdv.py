import socket
import threading
import json
import requests
import mysql.connector
import os
from colorama import Fore, Back, Style
from colorama import init
import time
import subprocess
import datetime


def loadJSON(path):
    with open(path, 'r') as file:
        data = json.load(file)
    return data


init()
config = loadJSON('config.json')
honeypots = config['honeypots']
database = config['database']
discord = config['discord']

db_conn = mysql.connector.connect(
    host=database['host'],
    user=database['user'],
    password=database['password'],
    database=database['database']
)


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def get_data(ip):
    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
    try:
        response = requests.get(url)
        data = response.json()

        if data['status'] == 'ok':
            subnet = data['data']['resource']
            asns = [(entry['asn'], entry['holder']) for entry in data['data']['asns']]
            return subnet, asns
        else:
            print("Error:", data.get('messages', ["Unknown error"])[0][1])
            return None, None

    except Exception as e:
        print("Error:", e)
        return None, None


def get_own_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except socket.error as e:
        print(f"Error: {e}")
        return None


def honeypot(port, protocol):
    try:
        if protocol == 'TCP':
            hp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol == 'UDP':
            hp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            print("Unsupported protocol")
            return

        hp_socket.bind(('0.0.0.0', port))
        hp_socket.listen(5) if protocol == 'TCP' else None

        while True:
            if protocol == 'TCP':
                conn, addr = hp_socket.accept()
                print(
                    f"{Fore.RED}[TCP]{Style.RESET_ALL} Connection from {addr[0]}:{addr[1]} to Honeypot on Port {port}")
            elif protocol == 'UDP':
                data, addr = hp_socket.recvfrom(1024)
                print(
                    f"{Fore.YELLOW}[UDP] {Style.RESET_ALL} Connection from {addr[0]}:{addr[1]} to Honeypot on Port {port}: {data}")

            ip = addr[0]
            subnet, asns = get_data(ip)
            service = next(
                (item['name'] for item in honeypots if item['port'] == port and item['protocol'] == protocol),
                "Unknown")

            asn_id, asn_name = asns[0] if asns else (None, None)
            if discord['useWebhooks']:
                sendToDiscord(ip, port, subnet, [(asn_id, asn_name)], protocol, service, "Test")

            now_utc = datetime.datetime.utcnow()
            utc_plus_2 = datetime.timedelta(hours=2)
            now_utc_plus_2 = now_utc + utc_plus_2

            timestamp_utc_plus_2 = now_utc_plus_2.strftime("%d.%m.%Y_%H:%M:%S")

            blockIP(addr[0])
            insert_into_db(ip, subnet, [(asn_id, asn_name)], port, protocol, service, "Test", timestamp_utc_plus_2)

    except Exception as ex:
        print(f"Error starting Honeypot on Port {port}. {str(ex)}")


def blockIP(ip):
    command = f"iptables -A INPUT -s {ip} -j DROP"

    try:
        subprocess.run(command, shell=True, check=True)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Blocked IP: {ip} successfully!")
    except Exception as ex:
        print(f"Error: {ex}", )


def insert_into_db(ip, subnet, asns, port, protocol, reason, log, date):
    try:
        asn_id, asn_name = asns[0] if asns else (None, None)
        cursor = db_conn.cursor()
        query = ("INSERT INTO bans (ip, subnet, asn, asnid, port, protocol, reason, log, date) VALUES (%s, %s, %s, "
                 "%s, %s, %s, %s, %s, %s)")
        cursor.execute(query, (ip, subnet, asn_name, asn_id, port, protocol, reason, log, date))
        db_conn.commit()
        cursor.close()
        print("Insert successful!")
    except Exception as e:
        print("Error:", e)


def sendToDiscord(ip, port, subnet, asns, protocol, reason, log):
    url = str(discord['webhookurl'])

    asn_id, asn_name = asns[0] if asns else (None, None)
    data = {"content": "", "username": "RMDV | Honeypot", "embeds": [
        {
            "description": f"\nIP: {ip}\nPort: {port}\nSubnet: {subnet}\nASN: {asn_name}\nASN-ID: {asn_id}\nProtocol: {protocol}\nReason: {reason}\nLog: {log}",
            "title": "[+] New Ban!",
            "color": 0xFF5733
        }
    ]}

    result = requests.post(url, json=data)

    try:
        result.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)


def menu():
    clear()
    ip = get_own_ip()
    print("""

    ____  __  _______ _    __
   / __ \/  |/  / __ \ |  / /
  / /_/ / /|_/ / / / / | / / 
 / _, _/ /  / / /_/ /| |/ /  
/_/ |_/_/  /_/_____/ |___/   
            made by @jonasdallmann
          
          """)
    print("")
    print(f"{Fore.YELLOW}Configuration:{Style.RESET_ALL}")
    print("")
    if discord['useWebhooks']:
        print(f"     Discord-Notifications: {Fore.GREEN}Activated{Style.RESET_ALL}")
    else:
        print(f"     Discord-Notifications: {Fore.RED}Deactivated{Style.RESET_ALL}")
    print("")
    print(f"     Host: {ip}")
    print("")
    print(f"     Database: {Fore.GREEN}Connected{Style.RESET_ALL}")
    print("")
    print("")
    print(f"[1] {Fore.GREEN}Start RMDV {Style.RESET_ALL}")
    print(f"[2] {Fore.RED}Exit RMDV {Style.RESET_ALL}")
    print("")
    x = input("> ")
    if x == "1":
        clear()
        main()
    elif x == "2":
        exit()
    else:
        clear()
        print("Unknown Input. Exiting...")
        time.sleep(3)
        exit()


def main():
    for honeypot_data in honeypots:
        port = honeypot_data['port']
        protocol = honeypot_data['protocol']
        print(f"{Fore.GREEN}[+] Honeypot on Port: {port} ({protocol}){Style.RESET_ALL}")
        honeypot_thread = threading.Thread(target=honeypot, args=(port, protocol))
        honeypot_thread.start()


if __name__ == "__main__":
    menu()

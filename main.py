#  Copyright (c) 2023.
#  ============================================================
#  Title: CSAK Tool
#  Subtitle: Cybersecurity Swiss Army Tool
#  Author: Ryan Collins
#  Date: 2023
#  Description: A tool for Cybersecurity tasks
#  TCP Port Scanning
#  UDP Port Scanning
#  Scan a URL with Nikto
#  Netdiscover (must be root!)
#  ============================================================

import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pexpect
from tqdm import tqdm


def scan_tcp_ports(ip, start_port, end_port=None, output_file=None):
    if end_port is None:
        end_port = 65535

    open_ports = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_tcp_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in tqdm(futures, total=len(futures), desc="Scanning TCP ports"):
            port = futures[future]
            if future.result():
                open_ports.append(port)
            if output_file:
                with open(output_file, 'w') as f:
                    f.write("Open TCP ports on {}: {}\n".format(ip, open_ports))
            else:
                print("Open TCP ports on {}: {}".format(ip, open_ports))
    return open_ports


def scan_udp_ports(ip, start_port, end_port=None, output_file=None):
    if end_port is None:
        end_port = 65535

    open_ports = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_udp_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in tqdm(futures, total=len(futures), desc="Scanning UDP ports"):
            port = futures[future]
            if future.result():
                open_ports.append(port)
            if output_file:
                with open(output_file, 'w') as f:
                    f.write("Open UDP ports on {}: {}\n".format(ip, open_ports))
            else:
                print("Open UDP ports on {}: {}".format(ip, open_ports))
    return open_ports


def scan_tcp_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0


def scan_udp_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)  # Set a timeout for the UDP socket
            sock.sendto(b'X', (ip, port))
            data, addr = sock.recvfrom(1024)
            print(f"UDP port {port} open on {ip}")
            return True
    except (socket.timeout, OSError):
        return False


# Nikto
def scan_with_nikto(url, output_file=None):
    try:
        # Run the Nikto command and capture the output
        command = f"nikto -host {url}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end='')
        process.wait()
        if output_file:
            with open(output_file, 'w') as f:
                for line in process.stdout:
                    f.write(line)
        else:
            for line in process.stdout:
                print(line, end='')
    except subprocess.CalledProcessError as e:
        print(f"Error executing Nikto: {e.output}")


# Netdiscover
def run_netdiscover(ip_range, output_file=None):
    try:
        # Run the netdiscover command and capture the output
        command = f"sudo netdiscover -r {ip_range}"
        process = pexpect.spawn(command)
        while True:
            try:
                line = process.readline()
            except pexpect.exceptions.TIMEOUT:
                break
            if not line:
                break
            line = line.decode().strip()
            print(line)
            if "Currently scanning: Finished!" in line:
                break
            if output_file:
                with open(output_file, 'w') as f:
                    while True:
                        try:
                            line = process.readline()
                        except pexpect.exceptions.TIMEOUT:
                            break
                        if not line:
                            break
                        line = line.decode().strip()
                        f.write(line + '\n')
                        print(line)
                        if "Currently scanning: Finished!" in line:
                            break
            else:
                while True:
                    try:
                        line = process.readline()
                    except pexpect.exceptions.TIMEOUT:
                        break
                    if not line:
                        break
                    line = line.decode().strip()
                    print(line)
                    if "Currently scanning: Finished!" in line:
                        break
        process.wait()
    except subprocess.CalledProcessError as e:
        print(f"Error executing netdiscover: {e.output}")


# Web Directory Scanning (using dirb)
def run_dirb(url, wordlist, output_file=None):
    try:
        # Run the dirb command and capture the output
        command = f"dirb {url} {wordlist} -o dirb.txt -S"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end='')
        process.wait()
        if output_file:
            with open(output_file, 'w') as f:
                for line in process.stdout:
                    f.write(line)
        else:
            for line in process.stdout:
                print(line, end='')
    except subprocess.CalledProcessError as e:
        print(f"Error executing Dirb: {e.output}")


def main():
    while True:
        print("""  ___       _             
 / (_)     | |            
|          | |   _   ,_   
|     |   ||/ \_|/  /  |  
 \___/ \_/|/\_/ |__/   |_/
         /|               
         \|               
                        
  ()         o          
  /\             ,   ,  
 /  \|  |  |_|  / \_/ \_
/(__/ \/ \/  |_/ \/  \/ 
                        
                        
  ___,                         
 /   |                         
|    |   ,_    _  _  _         
|    |  /  |  / |/ |/ |  |   | 
 \__/\_/   |_/  |  |  |_/ \_/|/
                            /| 
                            \| 
 ,                 _      
/|   /         o  | |     
 |__/   _  _      | |  _  
 | \   / |/ |  |  |/  |/  
 |  \_/  |  |_/|_/|__/|__/
                  |\      
                  |/      """)
        print("Welcome to the CSAK Tool!")
        print("Select a task:")
        print("1. TCP Port Scanning")
        print("2. UDP Port Scanning")
        print("3. Scan a URL with Nikto")
        print("4. Run netdiscover (must be root!)")
        print("5. Web Directory Scanning")
        print("6. Exit")
        choice = int(input())

        if choice == 1:
            ip = input("Enter the IP address to scan: ")
            scan_option = input("Enter 'all' to scan all ports or 'range' to specify start and end ports: ")
            output_file = input("Enter the output file path (or leave it blank to display results on the console): ")

            if scan_option.lower() == 'all':
                open_ports = scan_tcp_ports(ip, start_port=1, end_port=65535, output_file=output_file)
            elif scan_option.lower() == 'range':
                start_port = int(input("Enter the starting port: "))
                end_port = int(input("Enter the ending port: "))
                open_ports = scan_tcp_ports(ip, start_port=start_port, end_port=end_port, output_file=output_file)
            else:
                print("Invalid option. Please choose 'all' or 'range'.")
                return

            print("Open TCP ports on {}: {}".format(ip, open_ports))

        elif choice == 2:
            ip = input("Enter the IP address to scan: ")
            scan_option = input("Enter 'all' to scan all ports or 'range' to specify start and end ports: ")
            output_file = input("Enter the output file path (or leave it blank to display results on the console): ")

            if scan_option.lower() == 'all':
                open_ports = scan_udp_ports(ip, start_port=1, end_port=65535, output_file=output_file)
            elif scan_option.lower() == 'range':
                start_port = int(input("Enter the starting port: "))
                end_port = int(input("Enter the ending port: "))
                open_ports = scan_udp_ports(ip, start_port=start_port, end_port=end_port, output_file=output_file)
            else:
                print("Invalid option. Please choose 'all' or 'range'.")
                return

            print("Open UDP ports on {}: {}".format(ip, open_ports))

        elif choice == 3:
            url = input("Enter the URL you want to scan with Nikto: ")
            output_file = input("Enter the output file path (or leave it blank to display results on the console): ")
            scan_with_nikto(url, output_file=output_file)

        elif choice == 4:
            ip_range = input("Enter the IP address range (e.g., 192.168.2.1/24). "
                             "Press Ctrl+C to cancel the scan: ")
            output_file = input("Enter the output file path (or leave it blank to display results on the console): ")
            run_netdiscover(ip_range, output_file=output_file)

        elif choice == 5:
            url = input("Enter the URL you want to scan with Dirb: ")
            wordlist = input("Enter the path to the wordlist file: ")
            output_file = input("Enter the output file path (or leave it blank to display results on the console): ")
            run_dirb(url, wordlist, output_file=output_file)

        elif choice == 6:
            print("Exiting Cyber Swiss Army Knife Tool. Goodbye!")
            break  # Exit the loop and end the program

        else:
            print("Invalid option. Please choose a valid task.")


if __name__ == "__main__":
    main()

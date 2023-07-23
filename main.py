#  Copyright (c) 2023.
#  ============================================================
#  Title: CSAK Tool
#  Author: Ryan Collins
#  Date: 2023
#  Description: A tool for Cybersecurity tasks, including port scanning.
#  ============================================================

import getpass
import os
import signal
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from tqdm import tqdm


def scan_tcp_ports(ip, start_port, end_port=None):
    if end_port is None:
        end_port = 65535

    open_ports = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_tcp_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in tqdm(futures, total=len(futures), desc="Scanning TCP ports"):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return open_ports


def scan_udp_ports(ip, start_port, end_port=None):
    if end_port is None:
        end_port = 65535

    open_ports = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_udp_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in tqdm(futures, total=len(futures), desc="Scanning UDP ports"):
            port = futures[future]
            if future.result():
                open_ports.append(port)
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
def scan_with_nikto(url):
    try:
        # Run the Nikto command and capture the output in real-time
        command = f"nikto -url {url}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Print the output in real-time
        for line in process.stdout:
            print(line, end='')

        # Wait for the process to complete
        process.wait()
    except subprocess.CalledProcessError as e:
        print(f"Error executing Nikto: {e.output}")


# Netdiscover
def run_netdiscover(ip_range):
    try:
        # Get the password from the user
        password = getpass.getpass("Enter your password (will not be displayed): ")

        # Run the netdiscover command with sudo and capture the output
        command = f"sudo -S netdiscover -r {ip_range}"
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, preexec_fn=os.setsid)

        print("Netdiscover is running. Press Ctrl+C to stop the process.")
        print("Please wait...")

        # Print the output in real-time
        for line in process.stdout:
            print(line, end='')

        # Wait for the process to complete
        process.wait()
    except KeyboardInterrupt:
        print("Netdiscover process stopped.")
        # Terminate the process gracefully
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except subprocess.CalledProcessError as e:
        print(f"Error executing netdiscover: {e.stderr}")
    except Exception as ex:
        print(f"Error: {ex}")


def main():
    print("Welcome to the CSAK Tool!")
    print("Select a task:")
    print("1. TCP Port Scanning")
    print("2. UDP Port Scanning")
    print("3. Scan a URL with Nikto")
    print("4. Run netdiscover")
    choice = int(input())

    if choice == 1:
        ip = input("Enter the IP address to scan: ")
        scan_option = input("Enter 'all' to scan all ports or 'range' to specify start and end ports: ")

        if scan_option.lower() == 'all':
            open_ports = scan_tcp_ports(ip, start_port=1, end_port=65535)
        elif scan_option.lower() == 'range':
            start_port = int(input("Enter the starting port: "))
            end_port = int(input("Enter the ending port: "))
            open_ports = scan_tcp_ports(ip, start_port=start_port, end_port=end_port)
        elif choice == 3:
            url = input("Enter the URL you want to scan with Nikto: ")
            scan_with_nikto(url)
        else:
            print("Invalid option. Please choose 'all' or 'range'.")
            return

        print("Open TCP ports on {}: {}".format(ip, open_ports))

    elif choice == 2:
        ip = input("Enter the IP address to scan: ")
        scan_option = input("Enter 'all' to scan all ports or 'range' to specify start and end ports: ")

        if scan_option.lower() == 'all':
            open_ports = scan_udp_ports(ip, start_port=1, end_port=65535)
        elif scan_option.lower() == 'range':
            start_port = int(input("Enter the starting port: "))
            end_port = int(input("Enter the ending port: "))
            open_ports = scan_udp_ports(ip, start_port=start_port, end_port=end_port)
        else:
            print("Invalid option. Please choose 'all' or 'range'.")
            return

        print("Open UDP ports on {}: {}".format(ip, open_ports))

    elif choice == 3:
        url = input("Enter the URL you want to scan with Nikto: ")
        scan_with_nikto(url)
    elif choice == 4:
        ip_range = input("Enter the IP address range to scan with netdiscover (e.g., 192.168.2.1/24): ")
        run_netdiscover(ip_range)
    else:
        print("Invalid option. Please choose a valid task.")


if __name__ == "__main__":
    main()

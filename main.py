#  Copyright (c) 2023.
#
#  ============================================================
#  Title: CSAK Tool
#  Author: Ryan Collins
#  Date: 2023
#  Description: A tool for Cybersecurity tasks, including port scanning.
#  ============================================================

import socket
from concurrent.futures import ThreadPoolExecutor

from tqdm import tqdm


def scan_ports(ip_address, start_port=1, end_port=65535):
    open_ports = []
    total_ports = end_port - start_port + 1

    def scan_single_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Set a timeout for the connection attempt
                result = s.connect_ex((ip_address, port))
                if result == 0:  # Connection successful
                    open_ports.append(port)
        except socket.error:
            pass

    with ThreadPoolExecutor() as executor:
        list(tqdm(executor.map(scan_single_port, range(start_port, end_port + 1)), total=total_ports,
                  desc="Scanning ports", unit="port"))

    return open_ports


def main():
    print("Welcome to the CSAK Tool!")
    print("Select a task:")
    print("1. Port Scanning")
    # print("2. Other Task (Decide on another task here)")

    task_choice = input("Enter the number of the task you want to perform: ")

    if task_choice == "1":
        ip_address = input('Enter the IP address to scan: ')

        port_option = input('Enter "all" to scan all ports, or press Enter to specify a range: ')

        if port_option.lower() == 'all':
            open_ports = scan_ports(ip_address)
        else:
            start_port = int(input('Enter starting port: '))
            end_port = int(input('Enter ending port: '))
            open_ports = scan_ports(ip_address, start_port, end_port)

        if open_ports:
            print(f"Open ports on {ip_address}: {', '.join(map(str, open_ports))}")
        else:
            print(f"No open ports found on {ip_address}")
    # elif task_choice == "2":
    # Add code for the other task here
    # print("You selected the other task. Decide what you want to do next?.")
    else:
        print("Invalid choice. Please select a valid task.")


if __name__ == "__main__":
    main()

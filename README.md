## CSAK

### Cybersecurity Swiss Army Knife

![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Description

CSAK Tool is a Python program that provides various cybersecurity-related tasks. Currently, it includes a port
scanning feature that allows users to scan open ports on a given IP address, Scan a URL with Nikto, web directory
scanning with dirb, and Netdiscover to find network attached devices.

## Features

- TCP/UDP Scan for open ports on a specified IP address or IP address range.
- Scan a URL with Nikto
- Run Netdiscover (requires root!)
- Web directory scanning with dirb

## Prerequisites

- Python 3.x
- Libraries:
    - tqdm (for progress bar): You can install it using `pip install tqdm`
    - colorama
    - pexpect
    - ptyprocess

or use pip install -r requirements.txt

## How to Use

1. Clone the repository or download the `main.py` file.
2. Open a terminal or command prompt and navigate to the directory containing `main.py`.
3. Run the program using the following command:

```bash
python main.py
```

4. Follow the on-screen instructions to select the desired task and provide the necessary input (e.g., IP address, port
   range).

## Examples

### Port Scanning

- Enter the IP address to scan: `10.10.2.1`
- Enter "all" to scan all ports, or press Enter to specify a range.
- If "all" is selected, the program will scan all 65535 ports.
- If you specify a range, you need to provide the starting and ending ports.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! If you have any ideas, suggestions, or bug reports, please open an issue or submit a pull
request.

## Contact

For any inquiries, feel free to contact [hello@ryd3v.com](mailto:hello@ryd3v.com)

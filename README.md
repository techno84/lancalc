# LanCalc

LanCalc is a desktop application built with PyQt5, designed to calculate network configurations for Windows and Linux systems.

![image](https://github.com/user-attachments/assets/99458a02-5df0-4b0c-8948-4ad49d678d73)

[Download](https://github.com/lancalc/lancalc/releases)

It provides a user-friendly interface to compute essential network parameters such as network address, broadcast address, the minimum and maximum host addresses, and the number of hosts within a given subnet. 

Support IPv4 address formats, subnet masks and prefixes. This tool is particularly useful for network administrators and IT professionals who require quick calculations of network parameters.

## Quick Start

### Installation

Install LanCalc with one command:

```bash
pip3 install git+https://github.com/lancalc/lancalc.git
```

If the `lancalc` command is not found after installation, add the local packages path to PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

To permanently add to PATH, add this line to your `~/.bashrc` or `~/.zshrc`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## Running the Application

After installation, launch the application with the command:

```bash
lancalc
```



### Run

Launch the application:

```bash
lancalc
```

### Uninstall

```bash
pip3 uninstall -y lancalc
```

That's it! The application will start and automatically detect your current network settings.

## For Developers

### Prerequisites

Python 3.7+ is required, along with the following libraries:

```bash
pip3 install -r requirements.txt
```

### Installation for Development

Clone the repository and install in development mode:

```bash
git clone https://github.com/lancalc/lancalc.git
cd lancalc
pip3 install -e .
```

### Running from Source

```bash
python3 lancalc/main.py
```

### Development Tools

```bash
pip3 install pre-commit flake8 pytest pytest-qt
pre-commit install
pre-commit run --all-files
pre-commit autoupdate
```

### Running Tests
```bash
pytest -v
```

### Test Build
```bash
pip3 install git+file://$(pwd) && export PATH="$HOME/.local/bin:$PATH" && lancalc
```

## License

Distributed under the MIT License. See LICENSE for more information.

## Contact

[GitHub](https://github.com/lancalc/lancalc) [Telegram](https://t.me/wachawo)

## Notes

A /31 mask allows the use of 2 addresses. The first will be the network address, the last the broadcast address, and for connecting hosts we use these same addresses.

Limitations when using a /31 prefix:

Protocols that use L3 broadcast stop working.
In fact, at present there are almost no protocols left that rely on L3 broadcast in their operation. The main currently relevant protocols, such as OSPF, IS-IS, EIGRP, and BGP, use multicast or unicast addresses instead.
This limitation can even be seen as an advantage, because it increases resistance to DoS attacks based on broadcast traffic distribution.

Not all devices support /31 prefixes.
On Juniper and Cisco devices, you can safely use a /31 mask, although Cisco will issue a warning (% Warning: use /31 mask on non point-to-point interface cautiously).
ZyXEL, however, does not allow you to select a /31 mask at all.
As a result, there are additional limitations in network operation — from using equipment of different manufacturers to even using equipment from the same vendor but with different firmware versions.

If you are not concerned by the above limitations, you can confidently save addresses by using the /31 prefix.

The use of the /31 prefix is described in detail in RFC 3021 — Using 31-Bit Prefixes on IPv4 Point-to-Point Links.

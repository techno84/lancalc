#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LanCalc — GUI + CLI.

Changes:
- CLI via argparse: `lancalc 192.168.88.2/24` prints the result to stdout.
- If no argument is provided and GUI is unavailable (Linux without DISPLAY) or --no-gui is specified — print a notification to stdout and exit with code 2.
- --help from argparse.
- Logging to stderr (logging), computed answer — to stdout.
- GUI starts if no argument is provided and GUI is available.
"""
import argparse
import sys
import os
import re
import ipaddress
import iptools
import logging
import platform
import socket
import subprocess

# Try to import Qt — not required for CLI
try:
    from PyQt5.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox
    )
    from PyQt5.QtCore import Qt
    from PyQt5.QtCore import QEvent
    from PyQt5.QtGui import QFont, QKeyEvent
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

# Import version — support running as package/as script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from . import __version__
    VERSION = __version__
except Exception:
    try:
        import lancalc
        VERSION = lancalc.__version__
    except Exception:
        VERSION = "0.0.0"

logging.basicConfig(
    handlers=[logging.StreamHandler(sys.stderr)],
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s.%(funcName)s) - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def get_ip() -> str:
    """Return the primary local IPv4 address without external libs."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        # Fallback: hostname resolution (may return 127.0.0.1 in some setups)
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()


def cidr_from_netmask(mask: str) -> int:
    try:
        parts = [int(x) for x in mask.split('.')]
        return sum(bin(p).count('1') for p in parts)
    except Exception:
        return 24


def get_cidr(ip: str) -> int:
    """Best-effort CIDR detection using system tools; defaults to /24."""
    system = platform.system()
    try:
        if system == "Windows":
            # Parse 'ipconfig' output near the given IP
            out = subprocess.check_output(["ipconfig"], encoding="utf-8", errors="ignore")
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if ip in line:
                    for j in range(i, min(i+8, len(lines))):
                        if ("Subnet Mask" in lines[j]) or ("Маска подсети" in lines[j]):
                            mask = lines[j].split(":")[-1].strip()
                            return cidr_from_netmask(mask)
            return 24
        else:
            # Try `ip -o -4 addr show` to get prefix length
            try:
                out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], encoding="utf-8", errors="ignore")
                for line in out.splitlines():
                    # example token: 'inet 192.168.1.10/24'
                    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                    if m and m.group(1) == ip:
                        return int(m.group(2))
            except Exception:
                pass
            # Fallback default
            return 24
    except Exception:
        return 24


def validate_ip(ip_str: str) -> None:
    try:
        ipaddress.IPv4Address(ip_str)
    except Exception as e:
        raise ValueError(f"Invalid IPv4 address: {ip_str} ({e})")


def validate_prefix(prefix_str: str) -> int:
    try:
        p = int(prefix_str)
    except Exception:
        raise ValueError(f"Invalid CIDR prefix: {prefix_str}")
    if not (0 <= p <= 32):
        raise ValueError(f"CIDR out of range 0..32: {p}")
    return p


def calc_network(ip_cidr: str) -> dict:
    """Calculation of the network from a string like '192.168.88.254/24'. Returns a dict with fields.
    Logs are written to stderr, the result is used for stdout/GUI.
    """
    s = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<prefix>\d{1,2})$")
    m = s.match(ip_cidr.strip())
    if not m:
        raise ValueError("Expected ADDRESS in CIDR form, e.g. 192.168.88.254/24")
    ip = m.group('ip')
    prefix = validate_prefix(m.group('prefix'))
    validate_ip(ip)

    net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    total = net.num_addresses

    if total > 2:
        hostmin = ipaddress.IPv4Address(int(net.network_address) + 1)
        hostmax = ipaddress.IPv4Address(int(net.broadcast_address) - 1)
        hosts_str = str(total - 2)
    else:
        hostmin = net.network_address
        hostmax = net.broadcast_address
        hosts_str = f"{total}*"

    res = {
        "Network": str(net.network_address),
        "Prefix": f"/{prefix}",
        "Netmask": str(net.netmask),
        "Broadcast": str(net.broadcast_address),
        "Hostmin": str(hostmin),
        "Hostmax": str(hostmax),
        "Hosts": hosts_str,
    }
    return res


def print_result_stdout(res: dict) -> None:
    """Print only the result (stdout), without extra logs."""
    for k in ("Network", "Prefix", "Netmask", "Broadcast", "Hostmin", "Hostmax", "Hosts"):
        print(f"{k}: {res[k]}")


def is_headless_linux() -> bool:
    return sys.platform.startswith('linux') and not os.environ.get('DISPLAY')


if GUI_AVAILABLE:
    class ClickToCopyLineEdit(QLineEdit):
        def mousePressEvent(self, event):
            super().mousePressEvent(event)
            self.selectAll()
            QApplication.clipboard().setText(self.text())

    class IpInputLineEdit(QLineEdit):
        def focusInEvent(self, event):
            self.setStyleSheet("color: black;")
            super().focusInEvent(event)

    class LanCalc(QWidget):
        def __init__(self):
            super().__init__()
            logger.info("Initializing LanCalc application")
            self.init_ui()
            self.check_clipboard()
            logger.info("LanCalc application initialized successfully")

        def init_ui(self):
            try:
                main_layout = QVBoxLayout()
                self.setWindowTitle('LanCalc')
                input_width = 200
                font = QFont('Ubuntu', 12)
                readonly_style = "QLineEdit { background-color: #f0f0f0; color: #333; text-align: right; }"

                ip_layout = QHBoxLayout()
                ip_label = QLabel("IP Address")
                ip_label.setFont(font)
                self.ip_input = IpInputLineEdit(self)
                self.ip_input.setFont(font)
                self.ip_input.setFixedWidth(input_width)
                self.ip_input.setAlignment(Qt.AlignRight)
                ip_layout.addWidget(ip_label)
                ip_layout.addWidget(self.ip_input)
                # Defer parsing "IP/prefix" until focus is lost or Enter/Tab is pressed
                self.ip_input.installEventFilter(self)
                main_layout.addLayout(ip_layout)

                network_layout = QHBoxLayout()
                network_label = QLabel("Subnet")
                network_label.setFont(font)
                self.network_selector = QComboBox(self)
                self.network_selector.setFont(font)
                for cidr in range(33):
                    mask = str(ipaddress.IPv4Network(f'0.0.0.0/{cidr}', strict=False).netmask)
                    self.network_selector.addItem(f'{cidr}/{mask}')
                self.network_selector.setFixedWidth(input_width)
                network_layout.addWidget(network_label)
                network_layout.addWidget(self.network_selector)
                main_layout.addLayout(network_layout)

                self.set_default_values()

                self.calc_button = QPushButton('Calculate', self)
                self.calc_button.setFont(font)
                self.calc_button.clicked.connect(self.calculate_network)
                main_layout.addWidget(self.calc_button)

                self.network_output = ClickToCopyLineEdit(self)
                self.prefix_output = ClickToCopyLineEdit(self)
                self.netmask_output = ClickToCopyLineEdit(self)
                self.broadcast_output = ClickToCopyLineEdit(self)
                self.hostmin_output = ClickToCopyLineEdit(self)
                self.hostmax_output = ClickToCopyLineEdit(self)
                self.hosts_output = ClickToCopyLineEdit(self)

                for field in [
                    self.network_output,
                    self.prefix_output,
                    self.netmask_output,
                    self.broadcast_output,
                    self.hostmin_output,
                    self.hostmax_output,
                    self.hosts_output,
                ]:
                    field.setReadOnly(True)
                    field.setStyleSheet(readonly_style)
                    field.setAlignment(Qt.AlignRight)
                    field.setFont(font)
                    field.setFixedWidth(input_width)

                self.add_output_field(main_layout, "Network", self.network_output)
                self.add_output_field(main_layout, "Prefix", self.prefix_output)
                self.add_output_field(main_layout, "Netmask", self.netmask_output)
                self.add_output_field(main_layout, "Broadcast", self.broadcast_output)
                self.add_output_field(main_layout, "Hostmin", self.hostmin_output)
                self.add_output_field(main_layout, "Hostmax", self.hostmax_output)
                self.add_output_field(main_layout, "Hosts", self.hosts_output)

                self.link_label = QLabel(f'<a href="https://github.com/lancalc/lancalc">LanCalc {VERSION}</a>')
                self.link_label.setOpenExternalLinks(True)
                self.link_label.setAlignment(Qt.AlignCenter)
                self.link_label.setFont(QFont('Ubuntu', 11))
                main_layout.addWidget(self.link_label)

                self.setLayout(main_layout)
            except Exception as e:
                logger.error(f"Failed to initialize UI: {e}")

        def apply_cidr_from_text(self, text: str) -> None:
            """Apply CIDR from the IP input when triggered (focus out or Enter/Tab).
            Splits "IP/prefix" and updates selector when valid. Highlights red on invalid.
            """
            try:
                t = (text or "").strip()
                if not t:
                    self.ip_input.setStyleSheet("color: black;")
                    return
                if "/" in t:
                    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$", t)
                    if not m:
                        self.ip_input.setStyleSheet("color: red;")
                        return
                    ip_address, cidr = m.group(1), m.group(2)
                    if not self.validate_ip_address(ip_address):
                        self.ip_input.setStyleSheet("color: red;")
                        return
                    if cidr is not None and self.validate_cidr(cidr) and 0 <= int(cidr) < self.network_selector.count():
                        try:
                            self.ip_input.blockSignals(True)
                            self.ip_input.setText(ip_address)
                        finally:
                            self.ip_input.blockSignals(False)
                        self.network_selector.setCurrentIndex(int(cidr))
                        self.ip_input.setStyleSheet("color: black;")
                        return
                    # CIDR invalid or not present in selector
                    self.ip_input.setStyleSheet("color: red;")
                    return
                # No slash: validate full IP once on trigger
                if self.validate_ip_address(t):
                    self.ip_input.setStyleSheet("color: black;")
                else:
                    self.ip_input.setStyleSheet("color: red;")
            except Exception as e:
                logger.error(f"Error applying CIDR from IP input: {e}")
                self.ip_input.setStyleSheet("color: red;")

        def eventFilter(self, obj, event):
            try:
                if obj is self.ip_input:
                    if event.type() == QEvent.FocusOut:
                        self.apply_cidr_from_text(self.ip_input.text())
                        return False
                    if event.type() == QEvent.KeyPress:
                        key = event.key()
                        if key in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Tab):
                            self.apply_cidr_from_text(self.ip_input.text())
                            # Do not consume; keep normal behavior (focus move, calculate on return, etc.)
                            return False
                return super().eventFilter(obj, event)
            except Exception as e:
                logger.error(f"Error in event filter: {e}")
                return super().eventFilter(obj, event)

        def validate_ip_address(self, ip_str: str) -> bool:
            try:
                ipaddress.IPv4Address(ip_str)
                return True
            except ipaddress.AddressValueError as e:
                logger.warning(f"Invalid IP address format: {ip_str} - {e}")
                return False

        def validate_cidr(self, cidr_str: str) -> bool:
            try:
                cidr = int(cidr_str)
                if 0 <= cidr <= 32:
                    return True
                else:
                    logger.warning(f"CIDR out of range: {cidr_str} (must be 0-32)")
                    return False
            except ValueError as e:
                logger.warning(f"Invalid CIDR format: {cidr_str} - {e}")
                return False

        def check_clipboard(self):
            try:
                clipboard = QApplication.clipboard()
                clipboard_text = clipboard.text()
                logger.debug(f"Checking clipboard content: {clipboard_text}")
                match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/(\d{1,2}))?$', clipboard_text)
                if match:
                    ip_address = match.group(1)
                    cidr = match.group(3)
                    if self.validate_ip_address(ip_address):
                        self.ip_input.setText(ip_address)
                        logger.info(f"Auto-filled IP address from clipboard: {ip_address}")
                        if cidr and self.validate_cidr(cidr):
                            self.network_selector.setCurrentIndex(int(cidr))
                            logger.info(f"Auto-filled CIDR from clipboard: {cidr}")
                        else:
                            logger.warning(f"Invalid CIDR in clipboard: {cidr}")
                    else:
                        logger.warning(f"Invalid IP address in clipboard: {ip_address}")
            except Exception as e:
                logger.error(f"Error checking clipboard: {e}")

        def set_default_values(self):
            try:
                system = platform.system()
                if system == 'Linux':
                    import netifaces
                    gateways = netifaces.gateways()
                    default_interface = gateways['default'][netifaces.AF_INET][1]
                    addrs = netifaces.ifaddresses(default_interface)
                    ip_info = addrs[netifaces.AF_INET][0]
                    default_ip = ip_info['addr']
                    netmask = ip_info['netmask']
                    default_cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                elif system == 'Windows':
                    default_ip = get_ip()
                    default_cidr = get_cidr(default_ip)
                else:
                    default_ip = "127.0.0.1"
                    default_cidr = 8
                if self.validate_ip_address(default_ip):
                    self.ip_input.setText(default_ip)
                    self.network_selector.setCurrentIndex(default_cidr)
                    logger.info(f"Set default values - IP: {default_ip}, CIDR: {default_cidr}")
                else:
                    logger.warning(f"Invalid default IP address: {default_ip}")
            except Exception as e:
                logger.warning(f"Could not determine default network settings: {e}")

        def add_output_field(self, layout, label_text, line_edit):
            try:
                field_layout = QHBoxLayout()
                label = QLabel(label_text)
                label.setFont(QFont('Ubuntu', 13))
                line_edit.setReadOnly(True)
                field_layout.addWidget(label)
                field_layout.addWidget(line_edit)
                layout.addLayout(field_layout)
            except Exception as e:
                logger.error(f"Failed to add output field '{label_text}': {e}")

        def calculate_network(self, *args, **kwargs):
            try:
                ip_addr = self.ip_input.text().strip()
                prefix_text = self.network_selector.currentText()
                if not ip_addr:
                    raise ValueError("IP address is required")
                if not self.validate_ip_address(ip_addr):
                    raise ValueError(f"Invalid IP address format: {ip_addr}")
                prefix, netmask = prefix_text.split('/')
                if not self.validate_cidr(prefix):
                    raise ValueError(f"Invalid CIDR: {prefix}")

                rang = iptools.IpRange(f"{ip_addr}/{prefix}")
                rang_len = len(rang)
                network = rang[0] if rang_len > 0 else "-"
                broadcast = rang[-1] if rang_len > 2 else "-"
                hostmin = rang[1] if rang_len > 2 else rang[0]
                hostmax = rang[-2] if rang_len > 2 else rang[-1]
                hosts = rang_len - 2 if rang_len > 2 else rang_len
                hosts = str(hosts) if rang_len > 2 else f"{hosts}*"

                self.network_output.setText(network)
                self.broadcast_output.setText(broadcast)
                self.prefix_output.setText(f"/{prefix}")
                self.netmask_output.setText(netmask)
                self.hostmin_output.setText(hostmin)
                self.hostmax_output.setText(hostmax)
                self.hosts_output.setText(hosts)
                self.ip_input.setStyleSheet("color: black;")
            except Exception as e:
                logger.error(f"Unexpected error in network calculation: {e}")
                self.ip_input.setStyleSheet("color: red;")

        def keyPressEvent(self, event: QKeyEvent):
            try:
                if event.key() == Qt.Key_Return:
                    self.calculate_network()
                else:
                    super().keyPressEvent(event)
            except Exception as e:
                logger.error(f"Error handling key press event: {e}")

        def closeEvent(self, event):
            logger.info("LanCalc application closing")
            super().closeEvent(event)


def _run_gui() -> int:
    if not GUI_AVAILABLE:
        logger.critical("GUI is not available on this system (PyQt5 not installed or no display)")
        return 1
    app = QApplication(sys.argv)
    ex = LanCalc()  # type: ignore[name-defined]
    ex.show()
    return app.exec_()


def main(argv=None) -> int:

    parser = argparse.ArgumentParser(
        prog="lancalc",
        description=f"LanCalc {VERSION}: GUI + CLI IPv4 calculator. Result to stdout, logs to stderr.",
    )
    parser.add_argument(
        "address",
        nargs="?",
        help="IPv4 in CIDR, for example 192.168.88.2/24",
    )
    parser.add_argument(
        "--no-gui",
        action="store_true",
        help="Do not start GUI, work only in CLI (useful on server)",
    )

    args = parser.parse_args(argv)

    have_addr = bool(args.address)
    headless = is_headless_linux()
    force_cli = bool(args.no_gui)

    # Conditions for CLI: there is an address OR CLI is forced OR headless environment
    if have_addr or force_cli or headless:
        if not have_addr:
            # Argument is required: print a hint to stdout, code 2
            print("ADDRESS argument required, e.g. 192.168.88.2/24. Use --help for details.")
            return 2
        try:
            res = calc_network(args.address)
            print_result_stdout(res)
            return 0
        except Exception as e:
            logger.error(str(e))
            return 1

    # Otherwise — try GUI
    try:
        return _run_gui()
    except Exception as e:
        logger.critical(f"Failed to start GUI: {e}")
        # Last attempt — inform the user about the argument
        print("GUI is unavailable. Provide ADDRESS argument, e.g. 192.168.88.2/24. Use --help.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

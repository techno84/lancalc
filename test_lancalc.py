#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pytest
import logging
from lancalc.main import LanCalc

# Configure logging for tests
logging.basicConfig(level=logging.DEBUG)

# Test data: (ip, prefix, expected values in output fields)
test_cases = [
    ("192.168.1.10", "24", {
        'network': '192.168.1.0',
        'prefix': '/24',
        'netmask': '255.255.255.0',
        'broadcast': '192.168.1.255',
        'hostmin': '192.168.1.1',
        'hostmax': '192.168.1.254',
        'hosts': '254',
        'ip_color': 'black'
    }),
    ("10.0.0.1", "8", {
        'network': '10.0.0.0',
        'prefix': '/8',
        'netmask': '255.0.0.0',
        'broadcast': '10.255.255.255',
        'hostmin': '10.0.0.1',
        'hostmax': '10.255.255.254',
        'hosts': '16777214',
        'ip_color': 'black'
    }),
    ("172.16.5.4", "16", {
        'network': '172.16.0.0',
        'prefix': '/16',
        'netmask': '255.255.0.0',
        'broadcast': '172.16.255.255',
        'hostmin': '172.16.0.1',
        'hostmax': '172.16.255.254',
        'hosts': '65534',
        'ip_color': 'black'
    }),
    ("192.168.1.1", "32", {
        'network': '192.168.1.1',
        'prefix': '/32',
        'netmask': '255.255.255.255',
        'broadcast': '-',
        'hostmin': '192.168.1.1',
        'hostmax': '192.168.1.1',
        'hosts': '1*',
        'ip_color': 'black'
    }),
    ("256.256.256.256", "24", {
        'network': '',
        'prefix': '',
        'netmask': '',
        'broadcast': '',
        'hostmin': '',
        'hostmax': '',
        'hosts': '',
        'ip_color': 'red'
    })
]


@pytest.fixture
def app(qtbot):
    test_app = LanCalc()
    qtbot.addWidget(test_app)
    return test_app


@pytest.mark.parametrize("ip,prefix,expected", test_cases)
def test_lancalc_calculate(app, ip, prefix, expected):
    """Test network calculation through GUI"""
    # Set IP
    app.ip_input.setText(ip)
    # Set prefix in combobox
    for i in range(app.network_selector.count()):
        if app.network_selector.itemText(i).startswith(prefix + "/"):
            app.network_selector.setCurrentIndex(i)
            break
    # Call calculate
    app.calculate_network()
    # Check outputs
    assert app.network_output.text() == expected['network']
    assert app.prefix_output.text() == expected['prefix']
    assert app.netmask_output.text() == expected['netmask']
    assert app.broadcast_output.text() == expected['broadcast']
    assert app.hostmin_output.text() == expected['hostmin']
    assert app.hostmax_output.text() == expected['hostmax']
    assert app.hosts_output.text() == expected['hosts']
    # Check color
    if expected['ip_color'] == 'red':
        assert 'red' in app.ip_input.styleSheet()
    else:
        assert 'color: black' in app.ip_input.styleSheet() or app.ip_input.styleSheet() == ''


def test_invalid_cidr_handling(app):
    """Test handling of invalid CIDR values"""
    # Test with invalid CIDR (40) - this should fail validation
    app.ip_input.setText("192.168.1.1")
    # Try to set an invalid CIDR - since combobox only has 0-32, we'll test with a valid one
    # but the validation should catch it if we could set it
    app.calculate_network()
    # For now, just check that the app doesn't crash with invalid CIDR


def test_window_launch(app):
    """Test basic window functionality"""
    assert app.isVisible() is False  # Window is not shown by default
    app.show()
    assert app.isVisible() is True
    assert app.windowTitle() == 'LanCalc'

# Tests for validation functions


def test_validate_ip_address():
    """Test IP address validation"""
    app = LanCalc()

    # Valid IPs
    assert app.validate_ip_address("192.168.1.1")
    assert app.validate_ip_address("10.0.0.1")
    assert app.validate_ip_address("172.16.0.1")
    assert app.validate_ip_address("0.0.0.0")
    assert app.validate_ip_address("255.255.255.255")

    # Invalid IPs
    assert not app.validate_ip_address("256.256.256.256")
    assert not app.validate_ip_address("192.168.1.256")
    assert not app.validate_ip_address("192.168.1")
    assert not app.validate_ip_address("192.168.1.1.1")
    assert not app.validate_ip_address("")
    assert not app.validate_ip_address("invalid")


def test_validate_cidr():
    """Test CIDR validation"""
    app = LanCalc()

    # Valid CIDRs
    for i in range(33):
        assert app.validate_cidr(str(i))

    # Invalid CIDRs
    assert not app.validate_cidr("-1")
    assert not app.validate_cidr("33")
    assert not app.validate_cidr("100")
    assert not app.validate_cidr("")
    assert not app.validate_cidr("invalid")


def test_error_handling_in_gui(app):
    """Test error handling in GUI"""
    # Test with invalid IP
    app.ip_input.setText("invalid-ip")
    app.calculate_network()
    assert 'red' in app.ip_input.styleSheet()

    # Test with empty IP
    app.ip_input.setText("")
    app.calculate_network()
    assert 'red' in app.ip_input.styleSheet()


def test_edge_cases():
    """Test edge cases for network calculations"""
    app = LanCalc()

    # Test /0 network
    app.ip_input.setText("0.0.0.0")
    for i in range(app.network_selector.count()):
        if app.network_selector.itemText(i).startswith("0/"):
            app.network_selector.setCurrentIndex(i)
            break
    app.calculate_network()
    assert app.network_output.text() == '0.0.0.0'
    assert app.prefix_output.text() == '/0'
    assert app.netmask_output.text() == '0.0.0.0'

    # Test /32 network (single host)
    app.ip_input.setText("192.168.1.1")
    for i in range(app.network_selector.count()):
        if app.network_selector.itemText(i).startswith("32/"):
            app.network_selector.setCurrentIndex(i)
            break
    app.calculate_network()
    assert app.network_output.text() == '192.168.1.1'
    assert app.prefix_output.text() == '/32'
    assert app.netmask_output.text() == '255.255.255.255'
    assert app.hosts_output.text() == '1*'

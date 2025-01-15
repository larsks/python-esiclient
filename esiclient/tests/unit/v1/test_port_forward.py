import testtools
import ipaddress
from unittest import mock

from esiclient.v1.port_forward import PortSpec
from esiclient.v1.port_forward import Protocol
from esiclient.v1.port_forward import AddressOrPortArg
from esiclient.v1.port_forward import AddressOrNetworkArg
from esiclient.v1.port_forward import NetworkArg
from esiclient.v1.port_forward import SubnetArg
from esiclient.v1.port_forward import NetworkOpsMixin


class TestPortSpec(testtools.TestCase):
    test_params = (
        ("22", True, PortSpec(int_port=22, ext_port=22, protocol=Protocol.TCP)),
        ("22/udp", True, PortSpec(int_port=22, ext_port=22, protocol=Protocol.UDP)),
        ("2222:22", True, PortSpec(int_port=22, ext_port=2222, protocol=Protocol.TCP)),
        (
            "2222:22/tcp",
            True,
            PortSpec(int_port=22, ext_port=2222, protocol=Protocol.TCP),
        ),
        ("invalid", False, None),
        ("100000", False, None),
    )

    def test_port_spec(self):
        for spec, valid, expected in self.test_params:
            if valid:
                have = PortSpec.from_spec(spec)
                assert have == expected
            else:
                self.assertRaises(ValueError, PortSpec.from_spec, spec)


class TestAddressOrNetwork(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.cli = mock.Mock()

    def test_AddressOrNetwork_address(self):
        arg = AddressOrNetworkArg(self.cli)
        v = arg("10.10.10.10")
        assert v == ipaddress.ip_address("10.10.10.10")

    def test_AddressOrNetwork_network(self):
        self.cli.app.client_manager.sdk_connection.network.find_network.return_value = (
            "mynetwork"
        )
        arg = AddressOrNetworkArg(self.cli)
        v = arg("mynetwork")
        assert v == "mynetwork"

    def test_AddressOrNetwork_invalid(self):
        self.cli.app.client_manager.sdk_connection.network.find_network.return_value = (
            None
        )
        arg = AddressOrNetworkArg(self.cli)
        self.assertRaises(ValueError, arg, "mynetwork")


class TestAddressOrPort(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.cli = mock.Mock()

    def test_AddressOrPort_address(self):
        arg = AddressOrPortArg(self.cli)
        v = arg("10.10.10.10")
        assert v == ipaddress.ip_address("10.10.10.10")

    def test_AddressOrPort_port(self):
        self.cli.app.client_manager.sdk_connection.network.find_port.return_value = (
            "myport"
        )
        arg = AddressOrPortArg(self.cli)
        v = arg("myport")
        assert v == "myport"

    def test_AddressOrPort_invalid(self):
        self.cli.app.client_manager.sdk_connection.network.find_port.return_value = None
        arg = AddressOrPortArg(self.cli)
        self.assertRaises(ValueError, arg, "myport")


class TestNetworkArg(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.cli = mock.Mock()

    def test_Network_valid(self):
        self.cli.app.client_manager.sdk_connection.network.find_network.return_value = (
            "mynetwork"
        )
        arg = NetworkArg(self.cli)
        v = arg("mynetwork")
        assert v == "mynetwork"

    def test_Network_invalid(self):
        self.cli.app.client_manager.sdk_connection.network.find_network.return_value = (
            None
        )
        arg = NetworkArg(self.cli)
        self.assertRaises(ValueError, arg, "mynetwork")


class TestSubnetArg(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.cli = mock.Mock()

    def test_Subnet_valid(self):
        self.cli.app.client_manager.sdk_connection.network.find_subnet.return_value = (
            "mysubnet"
        )
        arg = SubnetArg(self.cli)
        v = arg("mysubnet")
        assert v == "mysubnet"

    def test_Subnet_invalid(self):
        self.cli.app.client_manager.sdk_connection.network.find_subnet.return_value = (
            None
        )
        arg = SubnetArg(self.cli)
        self.assertRaises(ValueError, arg, "mysubnet")


class TestNetworkOpsMixin(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.netops = NetworkOpsMixin()
        self.netops.app = mock.Mock()
        self.connection = mock.Mock()
        self.netops.app.client_manager.sdk_connection = self.connection
        self.port_1 = mock.Mock(id="port_1")
        self.port_2 = mock.Mock(id="port_2")

    def test_find_port_given_port(self):
        assert self.netops.find_port("myport") == "myport"

    def test_find_port_given_address(self):
        self.connection.network.ports.return_value = [self.port_1]
        assert self.netops.find_port(ipaddress.ip_address("10.10.10.10")) == self.port_1

    def test_find_port_given_missing_address(self):
        self.connection.network.ports.return_value = []
        self.assertRaises(
            KeyError, self.netops.find_port, ipaddress.ip_address("10.10.10.10")
        )

    def test_find_port_given_multiple_matches(self):
        self.connection.network.ports.return_value = [self.port_1, self.port_1]
        self.assertRaises(
            ValueError, self.netops.find_port, ipaddress.ip_address("10.10.10.10")
        )

    def test_find_or_create_port_given_existing_address(self):
        self.connection.network.ports.return_value = [self.port_1]
        assert (
            self.netops.find_or_create_port(ipaddress.ip_address("10.10.10.10"))
            == self.port_1
        )

    def test_find_or_create_port_no_network_provided(self):
        self.connection.network.ports.return_value = []
        self.assertRaises(
            ValueError,
            self.netops.find_or_create_port,
            ipaddress.ip_address("10.10.10.10"),
            internal_ip_network=None,
            internal_ip_subnet=None,
        )

    def test_find_or_create_port_given_missing_address(self):
        network = mock.Mock(id="network_1")
        subnet = mock.Mock(id="subnet_1", network_id="network_1")
        self.connection.network.ports.return_value = []
        self.connection.network.create_port.return_value = self.port_2
        assert (
            self.netops.find_or_create_port(
                ipaddress.ip_address("10.10.10.10"),
                internal_ip_network=network,
                internal_ip_subnet=subnet,
            )
            == self.port_2
        )
        self.connection.network.create_port.assert_called_with(
            name="esi-autocreated-10.10.10.10",
            network_id="network_1",
            fixed_ips=[{"subnet_id": "subnet_1", "ip_address": "10.10.10.10"}],
        )

    def test_find_or_create_port_search_subnets(self):
        network = mock.Mock(id="network_1")
        subnet = mock.Mock(
            id="subnet_1", network_id="network_1", cidr="10.10.10.0/24", ip_version=4
        )
        self.connection.network.ports.return_value = []
        self.connection.network.subnets.return_value = [subnet]
        self.connection.network.create_port.return_value = self.port_2
        assert (
            self.netops.find_or_create_port(
                ipaddress.ip_address("10.10.10.10"),
                internal_ip_network=network,
            )
            == self.port_2
        )
        self.connection.network.create_port.assert_called_with(
            name="esi-autocreated-10.10.10.10",
            network_id="network_1",
            fixed_ips=[{"subnet_id": "subnet_1", "ip_address": "10.10.10.10"}],
        )

    def test_find_or_create_port_search_subnets_unsuccessfully(self):
        network = mock.Mock(id="network_1")
        subnet = mock.Mock(
            id="subnet_1", network_id="network_1", cidr="11.11.11.0/24", ip_version=4
        )
        self.connection.network.ports.return_value = []
        self.connection.network.subnets.return_value = [subnet]
        self.connection.network.create_port.return_value = self.port_2
        self.assertRaises(
            KeyError,
            self.netops.find_or_create_port,
            ipaddress.ip_address("10.10.10.10"),
            internal_ip_network=network,
        )

    def test_find_floating_ip_given_address(self):
        self.connection.network.find_ip.return_value = "myfloatingip"
        assert (
            self.netops.find_floating_ip(ipaddress.ip_address("111.111.111.111"))
            == "myfloatingip"
        )

    def test_find_floating_ip_given_invalid_address(self):
        self.assertRaises(
            ValueError,
            self.netops.find_floating_ip,
            "invalid",
        )

    def test_find_floating_ip_given_missing_address(self):
        self.connection.network.find_ip.return_value = None
        self.assertRaises(
            KeyError,
            self.netops.find_floating_ip,
            ipaddress.ip_address("111.111.111.111"),
        )

    def test_find_or_create_floating_ip_given_network(self):
        self.connection.network.create_ip.return_value = "myfloatingip"
        assert (
            self.netops.find_or_create_floating_ip(mock.Mock(id="floating_network_1"))
            == "myfloatingip"
        )

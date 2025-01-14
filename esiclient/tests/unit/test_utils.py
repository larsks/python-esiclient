#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

from unittest import mock
from unittest import TestCase

from esiclient.tests.unit import utils as test_utils
from esiclient import utils


class TestGetNetworkDisplayName(TestCase):
    def test_get_network_display_name(self):
        network = test_utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "provider_segmentation_id": "777",
            }
        )

        results = utils.get_network_display_name(network)
        self.assertEqual("test_network (777)", results)

    def test_get_network_display_name_no_segmentation_id(self):
        network = test_utils.create_mock_object(
            {"id": "network_uuid", "name": "test_network"}
        )

        results = utils.get_network_display_name(network)
        self.assertEqual("test_network", results)


class TestGetNetworkInfoFromPort(TestCase):
    def setUp(self):
        super(TestGetNetworkInfoFromPort, self).setUp()
        self.network = test_utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "provider_segmentation_id": "777",
            }
        )

        self.neutron_client = mock.Mock()
        self.neutron_client.get_network.return_value = self.network
        self.networks_dict = {"network_uuid": self.network}

    def test_get_network_info_from_port(self):
        port = test_utils.create_mock_object(
            {
                "id": "port_uuid",
                "name": "test_port",
                "network_id": "network_uuid",
                "fixed_ips": [{"ip_address": "11.22.33.44"}],
            }
        )

        results = utils.get_network_info_from_port(
            port, self.neutron_client, self.networks_dict
        )
        self.assertEqual(("test_network (777)", "11.22.33.44"), results)

    def test_get_network_info_from_port_no_fixed_ips(self):
        port = test_utils.create_mock_object(
            {
                "id": "port_uuid",
                "name": "test_port",
                "network_id": "network_uuid",
                "fixed_ips": None,
            }
        )

        results = utils.get_network_info_from_port(
            port, self.neutron_client, self.networks_dict
        )
        self.assertEqual(("test_network (777)", ""), results)


class TestGetFullNetworkInfoFromPort(TestCase):
    def setUp(self):
        super(TestGetFullNetworkInfoFromPort, self).setUp()
        self.network1 = test_utils.create_mock_object(
            {
                "id": "network_uuid_1",
                "name": "test_network",
                "provider_segmentation_id": "777",
            }
        )
        self.network2 = test_utils.create_mock_object(
            {
                "id": "network_uuid_2",
                "name": "test_network_2",
                "provider_segmentation_id": "888",
            }
        )
        self.subport1 = test_utils.create_mock_object(
            {
                "id": "subport_uuid_1",
                "name": "test_subport_1",
                "network_id": "network_uuid_1",
                "fixed_ips": [{"ip_address": "11.22.33.44"}],
            }
        )
        self.subport2 = test_utils.create_mock_object(
            {
                "id": "subport_uuid_2",
                "name": "test_subport_2",
                "network_id": "network_uuid_2",
                "fixed_ips": [{"ip_address": "55.66.77.88"}],
            }
        )

        self.neutron_client = mock.Mock()

        self.networks_dict = {
            "network_uuid_1": self.network1,
            "network_uuid_2": self.network2,
        }

        def mock_network_get(network_uuid):
            if network_uuid == "network_uuid_1":
                return self.network1
            elif network_uuid == "network_uuid_2":
                return self.network2
            return None

        self.neutron_client.get_network.side_effect = mock_network_get

        def mock_port_get(port_uuid):
            if port_uuid == "subport_uuid_1":
                return self.subport1
            elif port_uuid == "subport_uuid_2":
                return self.subport2
            return None

        self.neutron_client.get_port.side_effect = mock_port_get

    def test_get_full_network_info_from_port(self):
        port = test_utils.create_mock_object(
            {
                "id": "port_uuid",
                "name": "test_port",
                "network_id": "network_uuid_1",
                "fixed_ips": [{"ip_address": "77.77.77.77"}],
                "trunk_details": {
                    "trunk_id": "trunk_uuid",
                    "sub_ports": [
                        {"segmentation_id": "777", "port_id": "subport_uuid_1"},
                        {"segmentation_id": "888", "port_id": "subport_uuid_2"},
                    ],
                },
            }
        )

        results = utils.get_full_network_info_from_port(
            port,
            self.neutron_client,
            self.networks_dict,
        )
        self.assertEqual(
            (
                ["test_network (777)", "test_network (777)", "test_network_2 (888)"],
                ["test_port", "test_subport_1", "test_subport_2"],
                ["77.77.77.77", "11.22.33.44", "55.66.77.88"],
            ),
            results,
        )

    def test_get_full_network_info_from_port_no_trunk(self):
        port = test_utils.create_mock_object(
            {
                "id": "port_uuid",
                "name": "test_port",
                "network_id": "network_uuid_1",
                "fixed_ips": [{"ip_address": "77.77.77.77"}],
                "trunk_details": None,
            }
        )

        results = utils.get_full_network_info_from_port(
            port, self.neutron_client, self.networks_dict
        )
        self.assertEqual(
            (["test_network (777)"], ["test_port"], ["77.77.77.77"]), results
        )


class TestGetPortName(TestCase):
    def setUp(self):
        super(TestGetPortName, self).setUp()
        self.network = test_utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "provider_segmentation_id": "777",
            }
        )

    def test_get_port_name(self):
        name = utils.get_port_name(self.network.name)
        self.assertEqual("esi-test_network", name)

    def test_get_port_name_prefix(self):
        name = utils.get_port_name(self.network.name, prefix="foo")
        self.assertEqual("esi-foo-test_network", name)

    def test_get_port_name_suffix(self):
        name = utils.get_port_name(self.network.name, suffix="bar")
        self.assertEqual("esi-test_network-bar", name)

    def test_get_port_name_prefix_and_suffix(self):
        name = utils.get_port_name(self.network.name, prefix="foo", suffix="bar")
        self.assertEqual("esi-foo-test_network-bar", name)


class TestGetOrCreatePort(TestCase):
    def setUp(self):
        super(TestGetOrCreatePort, self).setUp()
        self.port_name = "test_port"
        self.network = test_utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "provider_segmentation_id": "777",
            }
        )
        self.port = test_utils.create_mock_object(
            {"id": "port_uuid", "name": self.port_name, "status": "DOWN"}
        )

        self.neutron_client = mock.Mock()
        self.neutron_client.create_port.return_value = None

    def test_get_or_create_port_no_match(self):
        self.neutron_client.ports.return_value = []

        utils.get_or_create_port(self.port_name, self.network, self.neutron_client)
        self.neutron_client.create_port.assert_called_once_with(
            name=self.port_name,
            network_id=self.network.id,
            device_owner="baremetal:none",
        )

    def test_get_or_create_port_one_match(self):
        self.neutron_client.ports.return_value = [self.port]

        utils.get_or_create_port(self.port_name, self.network, self.neutron_client)
        self.neutron_client.create_port.assert_not_called()

    def test_get_or_create_port_many_matches(self):
        self.neutron_client.ports.return_value = [self.port, self.port]

        utils.get_or_create_port(self.port_name, self.network, self.neutron_client)
        self.neutron_client.create_port.assert_not_called()


class TestGetOrCreatePortByIP(TestCase):
    def setUp(self):
        super(TestGetOrCreatePortByIP, self).setUp()
        self.ip = "1.1.1.1"
        self.port_name = "test_port"
        self.network = test_utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "provider_segmentation_id": "777",
            }
        )
        self.subnet = test_utils.create_mock_object(
            {"id": "subnet_uuid", "name": "test_subnet"}
        )
        self.port = test_utils.create_mock_object(
            {"id": "port_uuid", "name": self.port_name, "status": "DOWN"}
        )

        self.neutron_client = mock.Mock()
        self.neutron_client.create_port.return_value = None

    def test_get_or_create_port_by_ip_no_match(self):
        self.neutron_client.ports.return_value = []

        utils.get_or_create_port_by_ip(
            self.ip, self.port_name, self.network, self.subnet, self.neutron_client
        )

        self.neutron_client.ports.assert_called_once_with(
            fixed_ips="ip_address=%s" % self.ip
        )
        self.neutron_client.create_port.assert_called_once_with(
            name=self.port_name,
            network_id=self.network.id,
            device_owner="baremetal:none",
            fixed_ips=[{"subnet_id": self.subnet.id, "ip_address": self.ip}],
        )

    def test_get_or_create_port_by_ip_match(self):
        self.neutron_client.ports.return_value = [self.port]

        utils.get_or_create_port_by_ip(
            self.ip, self.port_name, self.network, self.subnet, self.neutron_client
        )

        self.neutron_client.ports.assert_called_once_with(
            fixed_ips="ip_address=%s" % self.ip
        )
        self.neutron_client.create_port.assert_not_called()


class TestGetOrAssignPortFloatingIP(TestCase):
    def setUp(self):
        super(TestGetOrAssignPortFloatingIP, self).setUp()
        self.fixed_ip = "1.1.1.1"
        self.port_uuid = "port_uuid"
        self.port = test_utils.create_mock_object(
            {
                "id": self.port_uuid,
                "name": "port_name",
                "status": "DOWN",
                "fixed_ips": [
                    {"ip_address": self.fixed_ip, "subnet_id": "subnet_uuid"}
                ],
            }
        )
        self.fip_network = test_utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "provider_segmentation_id": "777",
            }
        )
        self.fip = test_utils.create_mock_object(
            {
                "id": "fip_uuid",
            }
        )

        self.neutron_client = mock.Mock()
        self.neutron_client.update_ip.return_value = None

    @mock.patch("esiclient.utils.get_or_create_floating_ip", autospec=True)
    def test_get_or_assign_port_floating_ip_free_fip(self, mock_gocfi):
        self.neutron_client.ips.return_value = [self.fip]

        utils.get_or_assign_port_floating_ip(
            self.port, self.fip_network, self.neutron_client
        )

        self.neutron_client.ips.assert_called_once_with(fixed_ip_address=self.fixed_ip)
        mock_gocfi.assert_not_called
        self.neutron_client.update_ip.assert_not_called

    @mock.patch("esiclient.utils.get_or_create_floating_ip", autospec=True)
    def test_get_or_assign_port_floating_ip_no_free_fip(self, mock_gocfi):
        self.neutron_client.ips.return_value = []
        mock_gocfi.return_value = self.fip

        utils.get_or_assign_port_floating_ip(
            self.port, self.fip_network, self.neutron_client
        )

        self.neutron_client.ips.assert_called_once_with(fixed_ip_address=self.fixed_ip)
        mock_gocfi.assert_called_once_with(self.fip_network, self.neutron_client)
        self.neutron_client.update_ip.assert_called_once_with(
            self.fip, port_id=self.port_uuid
        )


class TestGetOrCreateFloatingIP(TestCase):
    def setUp(self):
        super(TestGetOrCreateFloatingIP, self).setUp()
        self.fip_network = test_utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "provider_segmentation_id": "777",
            }
        )
        self.fip = test_utils.create_mock_object(
            {
                "id": "fip_uuid",
            }
        )
        self.neutron_client = mock.Mock()
        self.neutron_client.create_ip.return_value = None

    def test_get_or_create_floating_ip_exists(self):
        self.neutron_client.ips.return_value = [self.fip]

        utils.get_or_create_floating_ip(self.fip_network, self.neutron_client)

        self.neutron_client.ips.assert_called_once_with(
            network=self.fip_network.id, fixed_ip_address=""
        )
        self.neutron_client.create_ip.assert_not_called

    def test_get_or_create_floating_ip_not_exists(self):
        self.neutron_client.ips.return_value = []

        utils.get_or_create_floating_ip(self.fip_network, self.neutron_client)

        self.neutron_client.ips.assert_called_once_with(
            network=self.fip_network.id, fixed_ip_address=""
        )
        self.neutron_client.create_ip.assert_called_once_with(
            floating_network_id=self.fip_network.id
        )


class TestBootNodeFromURL(TestCase):
    def setUp(self):
        super(TestBootNodeFromURL, self).setUp()
        self.node_uuid = "node_uuid"
        self.url = "http://test.test/test"
        self.port_uuid = "port_uuid"

        self.ironic_client = mock.Mock()
        self.ironic_client.node.update.return_value = None
        self.ironic_client.node.vif_attach.return_value = None
        self.ironic_client.node.set_provision_state.return_value = None

    def test_boot_node_from_url(self):
        node_update = [
            {
                "path": "/instance_info/deploy_interface",
                "value": "ramdisk",
                "op": "add",
            },
            {"path": "/instance_info/boot_iso", "value": self.url, "op": "add"},
        ]

        utils.boot_node_from_url(
            self.node_uuid, self.url, self.port_uuid, self.ironic_client
        )

        self.ironic_client.node.update.assert_called_once_with(
            self.node_uuid, node_update
        )
        self.ironic_client.node.vif_attach.assert_called_once_with(
            self.node_uuid, self.port_uuid
        )
        self.ironic_client.node.set_provision_state.assert_called_once_with(
            self.node_uuid, "active"
        )


class TestCreateTrunk(TestCase):
    def setUp(self):
        super(TestCreateTrunk, self).setUp()

        self.network1 = test_utils.create_mock_object(
            {
                "id": "network_uuid_1",
                "name": "network1",
                "provider_segmentation_id": 111,
            }
        )
        self.network2 = test_utils.create_mock_object(
            {
                "id": "network_uuid_2",
                "name": "network2",
                "provider_segmentation_id": 222,
            }
        )
        self.network3 = test_utils.create_mock_object(
            {
                "id": "network_uuid_3",
                "name": "network3",
                "provider_segmentation_id": 333,
            }
        )
        self.port = test_utils.create_mock_object(
            {
                "id": "port_uuid_1",
                "network_id": "network_uuid_1",
                "name": "trunk-network1-trunk-port",
                "mac_address": "aa:aa:aa:aa:aa:aa",
            }
        )
        self.subport2 = test_utils.create_mock_object(
            {
                "id": "port_uuid_2",
                "network_id": "network_uuid_2",
                "name": "trunk-network2-sub-port",
                "mac_address": "bb:bb:bb:bb:bb:bb",
            }
        )
        self.subport3 = test_utils.create_mock_object(
            {
                "id": "port_uuid_3",
                "network_id": "network_uuid_3",
                "name": "trunk-network3-sub-port",
                "mac_address": "cc:cc:cc:cc:cc:cc",
            }
        )
        self.trunk = test_utils.create_mock_object(
            {
                "id": "trunk_uuid",
                "name": "trunk",
                "port_id": "port_uuid_1",
                "sub_ports": [
                    {
                        "port_id": "port_uuid_2",
                        "segmentation_id": "222",
                        "segmentation_type": "vlan",
                    },
                    {
                        "port_id": "port_uuid_3",
                        "segmentation_id": "333",
                        "segmentation_type": "vlan",
                    },
                ],
            }
        )

        self.neutron_client = mock.Mock()

        def mock_find_network(network_name):
            if network_name == "network1":
                return self.network1
            if network_name == "network2":
                return self.network2
            if network_name == "network3":
                return self.network3
            return None

        self.neutron_client.find_network.side_effect = mock_find_network

        def mock_create_port(name, network_id, device_owner):
            if network_id == "network_uuid_1":
                return self.port
            if network_id == "network_uuid_2":
                return self.subport2
            if network_id == "network_uuid_3":
                return self.subport3
            return None

        self.neutron_client.create_port.side_effect = mock_create_port

        self.neutron_client.ports.return_value = []

        self.neutron_client.create_trunk.return_value = self.trunk
        self.neutron_client.create_port.return_value = None

    def test_create_trunk(self):
        utils.create_trunk(
            self.neutron_client, "trunk", self.network1, ["network2", "network3"]
        )

        self.neutron_client.create_port.assert_has_calls(
            [
                mock.call(
                    name="esi-trunk-network1-trunk-port",
                    network_id="network_uuid_1",
                    device_owner="baremetal:none",
                ),
                mock.call(
                    name="esi-trunk-network2-sub-port",
                    network_id="network_uuid_2",
                    device_owner="baremetal:none",
                ),
                mock.call(
                    name="esi-trunk-network3-sub-port",
                    network_id="network_uuid_3",
                    device_owner="baremetal:none",
                ),
            ]
        )
        self.neutron_client.find_network.assert_has_calls(
            [mock.call("network2"), mock.call("network3")]
        )
        self.neutron_client.create_trunk.assert_called_once_with(
            name="trunk",
            port_id="port_uuid_1",
            sub_ports=[
                {
                    "port_id": "port_uuid_2",
                    "segmentation_type": "vlan",
                    "segmentation_id": 222,
                },
                {
                    "port_id": "port_uuid_3",
                    "segmentation_type": "vlan",
                    "segmentation_id": 333,
                },
            ],
        )


class TestDeleteTrunk(TestCase):
    def setUp(self):
        super(TestDeleteTrunk, self).setUp()

        self.trunk = test_utils.create_mock_object(
            {
                "id": "trunk_uuid",
                "name": "trunk",
                "port_id": "port_uuid_1",
                "sub_ports": [
                    {
                        "port_id": "port_uuid_2",
                        "segmentation_id": "222",
                        "segmentation_type": "vlan",
                    },
                    {
                        "port_id": "port_uuid_3",
                        "segmentation_id": "333",
                        "segmentation_type": "vlan",
                    },
                ],
            }
        )

        self.neutron_client = mock.Mock()
        self.neutron_client.delete_trunk.return_value = None
        self.neutron_client.delete_port.return_value = None

    def test_delete_trunk(self):
        utils.delete_trunk(self.neutron_client, self.trunk)

        self.neutron_client.delete_trunk.assert_called_once_with("trunk_uuid")
        self.neutron_client.delete_port.assert_has_calls(
            [
                mock.call("port_uuid_2"),
                mock.call("port_uuid_3"),
                mock.call("port_uuid_1"),
            ]
        )

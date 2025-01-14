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

from osc_lib import exceptions

from esiclient.tests.unit import base
from esiclient.tests.unit import utils
from esiclient.v1 import trunk


class TestList(base.TestCommand):
    def setUp(self):
        super(TestList, self).setUp()
        self.cmd = trunk.List(self.app, None)

        self.port1 = utils.create_mock_object(
            {
                "id": "port_uuid_1",
                "network_id": "network_uuid_1",
                "name": "trunk1-network1-trunk-port",
                "mac_address": "aa:aa:aa:aa:aa:aa",
            }
        )
        self.subport2 = utils.create_mock_object(
            {
                "id": "port_uuid_2",
                "network_id": "network_uuid_2",
                "name": "trunk1-network2-sub-port",
                "mac_address": "bb:bb:bb:bb:bb:bb",
            }
        )
        self.subport3 = utils.create_mock_object(
            {
                "id": "port_uuid_3",
                "network_id": "network_uuid_3",
                "name": "trunk1-network3-sub-port",
                "mac_address": "cc:cc:cc:cc:cc:cc",
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "id": "port_uuid_4",
                "network_id": "network_uuid_4",
                "name": "trunk2-network4-trunk-port",
                "mac_address": "dd:dd:dd:dd:dd:dd",
            }
        )
        self.subport3 = utils.create_mock_object(
            {
                "id": "port_uuid_5",
                "network_id": "network_uuid_5",
                "name": "trunk2-network5-sub-port",
                "mac_address": "ee:ee:ee:ee:ee",
            }
        )
        self.trunk1 = utils.create_mock_object(
            {
                "id": "trunk_uuid_1",
                "name": "trunk1",
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
        self.trunk2 = utils.create_mock_object(
            {
                "id": "trunk_uuid_2",
                "name": "trunk2",
                "port_id": "port_uuid_4",
                "sub_ports": [
                    {
                        "port_id": "port_uuid_5",
                        "segmentation_id": "555",
                        "segmentation_type": "vlan",
                    }
                ],
            }
        )

        self.app.client_manager.network.trunks.return_value = [self.trunk1, self.trunk2]
        self.app.client_manager.network.networks.return_value = []

        def mock_get_port(port_id):
            if port_id == "port_uuid_1":
                return self.port1
            if port_id == "port_uuid_4":
                return self.port2
            return None

        self.app.client_manager.network.get_port.side_effect = mock_get_port

    @mock.patch("esiclient.utils.get_full_network_info_from_port", autospec=True)
    def test_take_action(self, mock_gfnifp):
        def mock_get_fnifp(port, n_dict, client):
            if port.id == "port_uuid_1":
                return (
                    ["network1", "network2", "network3"],
                    [
                        "trunk1-network1-trunk-port",
                        "trunk1-network2-sub-port",
                        "trunk1-network3-sub-port",
                    ],
                    ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
                )
            if port.id == "port_uuid_4":
                return (
                    ["network4", "network5"],
                    ["trunk2-network4-trunk-port", "trunk2-network5-sub-port"],
                    ["4.4.4.4", "5.5.5.5"],
                )
            return None

        mock_gfnifp.side_effect = mock_get_fnifp

        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            ["Trunk", "Port", "Network"],
            [
                [
                    "trunk1",
                    "trunk1-network1-trunk-port\n"
                    "trunk1-network2-sub-port\n"
                    "trunk1-network3-sub-port",
                    "network1\nnetwork2\nnetwork3",
                ],
                [
                    "trunk2",
                    "trunk2-network4-trunk-port\ntrunk2-network5-sub-port",
                    "network4\nnetwork5",
                ],
            ],
        )

        self.assertEqual(expected, results)
        self.app.client_manager.network.get_port.assert_has_calls(
            [mock.call("port_uuid_1"), mock.call("port_uuid_4")]
        )
        mock_gfnifp.assert_has_calls(
            [
                mock.call(self.port1, self.app.client_manager.network, {}),
                mock.call(self.port2, self.app.client_manager.network, {}),
            ]
        )


class TestCreate(base.TestCommand):
    def setUp(self):
        super(TestCreate, self).setUp()
        self.cmd = trunk.Create(self.app, None)

        self.network = utils.create_mock_object(
            {
                "id": "network_uuid_1",
                "name": "network1",
                "provider_segmentation_id": 111,
            }
        )
        self.port = utils.create_mock_object(
            {
                "id": "port_uuid_1",
                "network_id": "network_uuid_1",
                "name": "trunk-network1-trunk-port",
                "mac_address": "aa:aa:aa:aa:aa:aa",
            }
        )
        self.trunk = utils.create_mock_object(
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

        self.app.client_manager.network.find_network.return_value = self.network

    @mock.patch("esiclient.utils.create_trunk", autospec=True)
    def test_take_action(self, mock_create_trunk):
        mock_create_trunk.return_value = self.trunk, self.port

        arglist = [
            "trunk",
            "--native-network",
            "network1",
            "--tagged-networks",
            "network2",
            "--tagged-networks",
            "network3",
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            ["Trunk", "Port", "Sub Ports"],
            [
                "trunk",
                "trunk-network1-trunk-port",
                [
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
            ],
        )

        self.assertEqual(expected, results)
        self.app.client_manager.network.find_network.assert_has_calls(
            [
                mock.call("network1"),
            ]
        )
        mock_create_trunk.assert_called_once_with(
            self.app.client_manager.network,
            "trunk",
            self.network,
            ["network2", "network3"],
        )


class TestDelete(base.TestCommand):
    def setUp(self):
        super(TestDelete, self).setUp()
        self.cmd = trunk.Delete(self.app, None)

        self.trunk = utils.create_mock_object(
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

        def mock_find_trunk(trunk_name):
            if trunk_name == "trunk":
                return self.trunk
            return None

        self.app.client_manager.network.find_trunk.side_effect = mock_find_trunk

        self.app.client_manager.network.delete_trunk.return_value = None
        self.app.client_manager.network.delete_port.return_value = None

    @mock.patch("esiclient.utils.delete_trunk", autospec=True)
    def test_take_action(self, mock_delete_trunk):
        arglist = ["trunk"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.network.find_trunk.assert_called_once_with("trunk")
        mock_delete_trunk.assert_called_once_with(
            self.app.client_manager.network, self.trunk
        )

    @mock.patch("esiclient.utils.delete_trunk", autospec=True)
    def test_take_action_no_trunk(self, mock_delete_trunk):
        arglist = ["trunk2"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no trunk named trunk2",
            self.cmd.take_action,
            parsed_args,
        )
        mock_delete_trunk.assert_not_called


class TestAddNetwork(base.TestCommand):
    def setUp(self):
        super(TestAddNetwork, self).setUp()
        self.cmd = trunk.AddNetwork(self.app, None)

        self.network2 = utils.create_mock_object(
            {
                "id": "network_uuid_2",
                "name": "network2",
                "provider_segmentation_id": 222,
            }
        )
        self.network3 = utils.create_mock_object(
            {
                "id": "network_uuid_3",
                "name": "network3",
                "provider_segmentation_id": 333,
            }
        )
        self.subport2 = utils.create_mock_object(
            {
                "id": "port_uuid_2",
                "network_id": "network_uuid_2",
                "name": "trunk-network2-sub-port",
                "mac_address": "bb:bb:bb:bb:bb:bb",
            }
        )
        self.subport3 = utils.create_mock_object(
            {
                "id": "port_uuid_3",
                "network_id": "network_uuid_3",
                "name": "trunk-network3-sub-port",
                "mac_address": "cc:cc:cc:cc:cc:cc",
            }
        )
        self.trunk = utils.create_mock_object(
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

        def mock_find_trunk(trunk_name):
            if trunk_name == "trunk":
                return self.trunk
            return None

        self.app.client_manager.network.find_trunk.side_effect = mock_find_trunk

        def mock_find_network(network_name):
            if network_name == "network2":
                return self.network2
            if network_name == "network3":
                return self.network3
            return None

        self.app.client_manager.network.find_network.side_effect = mock_find_network

        def mock_create_port(name, network_id, device_owner):
            if network_id == "network_uuid_2":
                return self.subport2
            if network_id == "network_uuid_3":
                return self.subport3
            return None

        self.app.client_manager.network.create_port.side_effect = mock_create_port

        self.app.client_manager.network.ports.return_value = []

        self.app.client_manager.network.add_trunk_subports.return_value = self.trunk

    def test_take_action(self):
        arglist = [
            "trunk",
            "--tagged-networks",
            "network2",
            "--tagged-networks",
            "network3",
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            ["Trunk", "Sub Ports"],
            [
                "trunk",
                [
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
            ],
        )

        self.assertEqual(expected, results)
        self.app.client_manager.network.find_trunk.assert_called_once_with("trunk")
        self.app.client_manager.network.create_port.assert_has_calls(
            [
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
        self.app.client_manager.network.find_network.assert_has_calls(
            [mock.call("network2"), mock.call("network3")]
        )
        self.app.client_manager.network.add_trunk_subports.assert_called_once_with(
            "trunk_uuid",
            [
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

    def test_take_action_no_networks(self):
        arglist = ["trunk"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no networks specified",
            self.cmd.take_action,
            parsed_args,
        )

    def test_take_action_unknown_network(self):
        arglist = [
            "trunk",
            "--tagged-networks",
            "network2",
            "--tagged-networks",
            "network4",
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no network named network4",
            self.cmd.take_action,
            parsed_args,
        )

    def test_take_action_no_trunk(self):
        arglist = [
            "trunk2",
            "--tagged-networks",
            "network2",
            "--tagged-networks",
            "network3",
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no trunk named trunk2",
            self.cmd.take_action,
            parsed_args,
        )


class TestRemoveNetwork(base.TestCommand):
    def setUp(self):
        super(TestRemoveNetwork, self).setUp()
        self.cmd = trunk.RemoveNetwork(self.app, None)

        self.network2 = utils.create_mock_object(
            {
                "id": "network_uuid_2",
                "name": "network2",
                "provider_segmentation_id": 222,
            }
        )
        self.network3 = utils.create_mock_object(
            {
                "id": "network_uuid_3",
                "name": "network3",
                "provider_segmentation_id": 333,
            }
        )
        self.subport2 = utils.create_mock_object(
            {
                "id": "port_uuid_2",
                "network_id": "network_uuid_2",
                "name": "trunk-network2-sub-port",
                "mac_address": "bb:bb:bb:bb:bb:bb",
            }
        )
        self.subport3 = utils.create_mock_object(
            {
                "id": "port_uuid_3",
                "network_id": "network_uuid_3",
                "name": "trunk-network3-sub-port",
                "mac_address": "cc:cc:cc:cc:cc:cc",
            }
        )
        self.trunk = utils.create_mock_object(
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

        def mock_find_trunk(trunk_name):
            if trunk_name == "trunk":
                return self.trunk
            return None

        self.app.client_manager.network.find_trunk.side_effect = mock_find_trunk

        self.app.client_manager.network.delete_trunk_subports.return_value = self.trunk

        self.app.client_manager.network.delete_port.return_value = None

    def test_take_action(self):
        arglist = [
            "trunk",
            "--tagged-networks",
            "network2",
            "--tagged-networks",
            "network3",
        ]
        verifylist = []

        def mock_find_port(port_name):
            if port_name == "esi-trunk-network2-sub-port":
                return self.subport2
            if port_name == "esi-trunk-network3-sub-port":
                return self.subport3
            return None

        self.app.client_manager.network.find_port.side_effect = mock_find_port

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.network.find_trunk.assert_called_once_with("trunk")
        self.app.client_manager.network.find_port.assert_has_calls(
            [
                mock.call("esi-trunk-network2-sub-port"),
                mock.call("esi-trunk-network3-sub-port"),
            ]
        )
        self.app.client_manager.network.delete_trunk_subports.assert_called_once_with(
            "trunk_uuid", [{"port_id": "port_uuid_2"}, {"port_id": "port_uuid_3"}]
        )

        self.app.client_manager.network.delete_port.assert_has_calls(
            [mock.call("port_uuid_2"), mock.call("port_uuid_3")]
        )

    def test_take_action_no_networks(self):
        arglist = ["trunk"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no networks specified",
            self.cmd.take_action,
            parsed_args,
        )

    def test_take_action_port_not_found(self):
        arglist = ["trunk", "--tagged-networks", "network2"]
        verifylist = []

        self.app.client_manager.network.find_port.return_value = None

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: network2 is not attached to trunk",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.network.find_trunk.assert_called_once_with("trunk")
        self.app.client_manager.network.find_port.assert_called_once_with(
            "esi-trunk-network2-sub-port"
        )
        self.app.client_manager.network.delete_trunk_subports.assert_not_called()
        self.app.client_manager.network.delete_port.assert_not_called()

    def test_take_action_no_trunk(self):
        arglist = [
            "trunk2",
            "--tagged-networks",
            "network2",
            "--tagged-networks",
            "network3",
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no trunk named trunk2",
            self.cmd.take_action,
            parsed_args,
        )

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
from esiclient.v1 import switch


class TestListVLAN(base.TestCommand):
    def setUp(self):
        super(TestListVLAN, self).setUp()
        self.cmd = switch.ListVLAN(self.app, None)

        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/1",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_1"},
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/2",
                },
                "internal_info": {},
            }
        )
        self.port3 = utils.create_mock_object(
            {
                "uuid": "port_uuid_3",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/3",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_2"},
            }
        )
        self.port4 = utils.create_mock_object(
            {
                "uuid": "port_uuid_4",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/4",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_3"},
            }
        )
        self.port5 = utils.create_mock_object(
            {
                "uuid": "port_uuid_5",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch2",
                    "port_id": "Ethernet1/5",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_4"},
            }
        )
        self.network1 = utils.create_mock_object(
            {
                "id": "network_uuid1",
                "name": "test_network1",
                "network_type": "vlan",
                "provider_segmentation_id": "100",
                "subnet_ids": ["subnet_uuid1"],
            }
        )
        self.network2 = utils.create_mock_object(
            {
                "id": "network_uuid2",
                "name": "test_network2",
                "network_type": "vlan",
                "provider_segmentation_id": "200",
                "subnet_ids": ["subnet_uuid2"],
            }
        )
        self.network3 = utils.create_mock_object(
            {
                "id": "network_uuid3",
                "name": "test_network3",
                "network_type": "vlan",
                "provider_segmentation_id": "300",
                "subnet_ids": ["subnet_uuid3"],
            }
        )
        self.network4 = utils.create_mock_object(
            {
                "id": "network_uuid4",
                "name": "test_network4",
                "network_type": "vlan",
                "provider_segmentation_id": "400",
                "subnet_ids": ["subnet_uuid4"],
            }
        )
        self.neutron_port1 = utils.create_mock_object(
            {
                "id": "neutron_port_uuid_1",
                "network_id": "network_uuid1",
                "fixed_ips": [{"subnet_id": "subnet_uuid1"}],
                "trunk_details": {"sub_ports": [{"port_id": "neutron_subport_uuid_1"}]},
            }
        )
        self.neutron_port2 = utils.create_mock_object(
            {
                "id": "neutron_port_uuid_2",
                "network_id": "network_uuid1",
                "fixed_ips": [{"subnet_id": "subnet_uuid1"}],
                "trunk_details": {},
            }
        )
        self.neutron_port3 = utils.create_mock_object(
            {
                "id": "neutron_port_uuid_3",
                "network_id": "network_uuid2",
                "fixed_ips": [{"subnet_id": "subnet_uuid2"}],
                "trunk_details": {},
            }
        )
        self.neutron_port4 = utils.create_mock_object(
            {
                "id": "neutron_port_uuid_4",
                "network_id": "network_uuid1",
                "fixed_ips": [{"subnet_id": "subnet_uuid1"}],
                "trunk_details": {},
            }
        )
        self.neutron_subport1 = utils.create_mock_object(
            {
                "id": "neutron_subport_uuid_1",
                "network_id": "network_uuid4",
                "fixed_ips": [{"subnet_id": "subnet_uuid4"}],
                "trunk_details": {},
            }
        )

        self.app.client_manager.network.networks.return_value = [
            self.network1,
            self.network2,
            self.network3,
            self.network4,
        ]
        self.app.client_manager.network.ports.return_value = [
            self.neutron_port1,
            self.neutron_port2,
            self.neutron_port3,
            self.neutron_port4,
            self.neutron_subport1,
        ]
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
            self.port3,
            self.port4,
            self.port5,
        ]

    def test_take_action(self):
        arglist = ["switch1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            ["VLAN", "Ports"],
            [
                ["100", ["Ethernet1/1", "Ethernet1/3"]],
                ["200", ["Ethernet1/4"]],
                ["300", []],
                ["400", ["Ethernet1/1"]],
            ],
        )
        self.assertEqual(expected, results)
        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan"
        )
        self.app.client_manager.network.ports.assert_called_once


class TestListSwitchPort(base.TestCommand):
    def setUp(self):
        super(TestListSwitchPort, self).setUp()
        self.cmd = switch.ListSwitchPort(self.app, None)

        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/1",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_1"},
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/2",
                },
                "internal_info": {},
            }
        )
        self.port3 = utils.create_mock_object(
            {
                "uuid": "port_uuid_3",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/3",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_2"},
            }
        )
        self.port4 = utils.create_mock_object(
            {
                "uuid": "port_uuid_3",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch2",
                    "port_id": "Ethernet1/4",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_3"},
            }
        )
        self.port5 = utils.create_mock_object(
            {
                "uuid": "port_uuid_3",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/5",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_X"},
            }
        )
        self.neutron_port1 = utils.create_mock_object(
            {
                "id": "neutron_port_uuid_1",
                "network_id": "network_uuid1",
                "fixed_ips": [{"subnet_id": "subnet_uuid1"}],
                "trunk_details": {"sub_ports": [{"port_id": "neutron_subport_uuid_1"}]},
            }
        )
        self.neutron_port2 = utils.create_mock_object(
            {
                "id": "neutron_port_uuid_2",
                "network_id": "network_uuid1",
                "fixed_ips": [{"subnet_id": "subnet_uuid1"}],
                "trunk_details": {},
            }
        )
        self.neutron_port3 = utils.create_mock_object(
            {
                "id": "neutron_port_uuid_3",
                "network_id": "network_uuid1",
                "fixed_ips": [{"subnet_id": "subnet_uuid1"}],
                "trunk_details": {},
            }
        )

        self.app.client_manager.network.ports.return_value = [
            self.neutron_port1,
            self.neutron_port2,
            self.neutron_port3,
        ]
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
            self.port3,
            self.port4,
            self.port5,
        ]
        self.app.client_manager.network.networks.return_value = []

    @mock.patch("esiclient.utils.get_full_network_info_from_port", autospec=True)
    def test_take_action(self, mock_gfnifp):
        def mock_gfnifp_call(np, n_dict, client):
            if np.id == "neutron_port_uuid_1":
                return ["net1 (100)", "net2 (200)"], [], []
            elif np.id == "neutron_port_uuid_2":
                return ["net1 (100)"], [], []
            return [], [], []

        mock_gfnifp.side_effect = mock_gfnifp_call

        arglist = ["switch1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            ["Port", "VLANs"],
            [
                ["Ethernet1/1", "net1 (100)\nnet2 (200)"],
                ["Ethernet1/2", ""],
                ["Ethernet1/3", "net1 (100)"],
                ["Ethernet1/5", ""],
            ],
        )
        self.assertEqual(expected, results)
        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.ports.assert_called_once
        self.assertEqual(mock_gfnifp.call_count, 2)


class TestList(base.TestCommand):
    def setUp(self):
        super(TestList, self).setUp()
        self.cmd = switch.List(self.app, None)

        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "switch_id": "e4:c7:22:c0:0b:69",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_1"},
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "switch_id": "e4:c7:22:c0:0b:69",
                },
                "internal_info": {},
            }
        )
        self.port3 = utils.create_mock_object(
            {
                "uuid": "port_uuid_3",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch2",
                    "switch_id": "aa:aa:aa:aa:aa:aa",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_2"},
            }
        )
        self.port4 = utils.create_mock_object(
            {
                "uuid": "port_uuid_3",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch3",
                    "switch_id": "bb:bb:bb:bb:bb:bb",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_3"},
            }
        )

        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
            self.port3,
            self.port4,
        ]

    def test_take_action(self):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            ["Switch Name", "Switch ID"],
            [
                ["switch1", "e4:c7:22:c0:0b:69"],
                ["switch2", "aa:aa:aa:aa:aa:aa"],
                ["switch3", "bb:bb:bb:bb:bb:bb"],
            ],
        )
        self.assertEqual(expected, results)
        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)


class TestEnableAccessPort(base.TestCommand):
    def setUp(self):
        super(TestEnableAccessPort, self).setUp()
        self.cmd = switch.EnableAccessPort(self.app, None)

        self.node = utils.create_mock_object(
            {
                "uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "name": "node1",
            }
        )
        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/1",
                },
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/2",
                },
            }
        )
        self.network = utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "network_type": "vlan",
                "provider_segmentation_id": "100",
                "subnet_ids": ["subnet_uuid"],
            }
        )
        self.neutron_port = utils.create_mock_object(
            {
                "id": "neutron_port_uuid",
                "network_id": "network_uuid",
                "name": "node1-port",
                "mac_address": "bb:bb:bb:bb:bb:bb",
                "fixed_ips": [{"ip_address": "2.2.2.2"}],
                "trunk_details": None,
            }
        )

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.network.networks.return_value = [self.network]
        mock_gpn.return_value = "node1-port"
        mock_gocp.return_value = self.neutron_port

        arglist = ["switch1", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.baremetal.node.get.assert_called_once_with(
            "11111111-2222-3333-4444-aaaaaaaaaaaa"
        )
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="100"
        )
        mock_gpn.assert_called_once_with("test_network", prefix="node1")
        mock_gocp.assert_called_once_with(
            "node1-port", self.network, self.app.client_manager.network
        )
        self.app.client_manager.baremetal.node.vif_attach.assert_called_once_with(
            "11111111-2222-3333-4444-aaaaaaaaaaaa", "neutron_port_uuid"
        )

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_vlan(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = []

        arglist = ["switch1", "Ethernet1/1", "200"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: VLAN ID unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="200"
        )
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_switchport(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = [self.network]

        arglist = ["switch1", "Ethernet1/3", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_not_called
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_switch(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = [self.network]

        arglist = ["switch2", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_not_called
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called


class TestDisableAccessPort(base.TestCommand):
    def setUp(self):
        super(TestDisableAccessPort, self).setUp()
        self.cmd = switch.DisableAccessPort(self.app, None)

        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/1",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_1"},
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/2",
                },
                "internal_info": {},
            }
        )

    def test_take_action(self):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]

        arglist = ["switch1", "Ethernet1/1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.baremetal.node.vif_detach.assert_called_once_with(
            "11111111-2222-3333-4444-aaaaaaaaaaaa", "neutron_port_uuid_1"
        )

    def test_take_action_unknown_switchport(self):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]

        arglist = ["switch1", "Ethernet1/3"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.baremetal.node.vif_detach.assert_not_called

    def test_take_action_unknown_switch(self):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]

        arglist = ["switch2", "Ethernet1/1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.baremetal.node.vif_detach.assert_not_called

    def test_take_action_no_neutron_port(self):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]

        arglist = ["switch1", "Ethernet1/2"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: No neutron port found for switchport",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.baremetal.node.vif_detach.assert_not_called


class TestEnableTrunkPort(base.TestCommand):
    def setUp(self):
        super(TestEnableTrunkPort, self).setUp()
        self.cmd = switch.EnableTrunkPort(self.app, None)

        self.node = utils.create_mock_object(
            {
                "uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "name": "node1",
            }
        )
        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/1",
                },
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/2",
                },
            }
        )
        self.network = utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "network_type": "vlan",
                "provider_segmentation_id": "100",
                "subnet_ids": ["subnet_uuid"],
            }
        )
        self.neutron_port = utils.create_mock_object(
            {
                "id": "neutron_port_uuid",
                "network_id": "network_uuid",
                "name": "node1-port",
                "mac_address": "bb:bb:bb:bb:bb:bb",
                "fixed_ips": [{"ip_address": "2.2.2.2"}],
                "trunk_details": None,
            }
        )
        self.trunk = utils.create_mock_object(
            {
                "id": "trunk_uuid",
                "name": "trunk",
                "port_id": "neutron_port_uuid",
            }
        )

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.network.networks.return_value = [self.network]
        self.app.client_manager.network.create_trunk.return_value = self.trunk
        mock_gpn.return_value = "node1-port-trunk-port"
        mock_gocp.return_value = self.neutron_port

        arglist = ["switch1", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.baremetal.node.get.assert_called_once_with(
            "11111111-2222-3333-4444-aaaaaaaaaaaa"
        )
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="100"
        )
        mock_gpn.assert_called_once_with(
            "test_network", prefix="switch1-Ethernet1/1", suffix="trunk-port"
        )
        mock_gocp.assert_called_once_with(
            "node1-port-trunk-port", self.network, self.app.client_manager.network
        )
        self.app.client_manager.network.create_trunk.assert_called_once_with(
            name="switch1-Ethernet1/1", port_id="neutron_port_uuid"
        )
        self.app.client_manager.baremetal.node.vif_attach.assert_called_once_with(
            "11111111-2222-3333-4444-aaaaaaaaaaaa", "neutron_port_uuid"
        )

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_vlan(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = []

        arglist = ["switch1", "Ethernet1/1", "200"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: VLAN ID unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="200"
        )
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called
        self.app.client_manager.network.create_trunk.assert_not_called

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_switchport(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = [self.network]

        arglist = ["switch1", "Ethernet1/3", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_not_called
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called
        self.app.client_manager.network.create_trunk.assert_not_called

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_switch(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = [self.network]

        arglist = ["switch2", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_not_called
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called
        self.app.client_manager.network.create_trunk.assert_not_called


class TestDisableTrunkPort(base.TestCommand):
    def setUp(self):
        super(TestDisableTrunkPort, self).setUp()
        self.cmd = switch.DisableTrunkPort(self.app, None)

        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/1",
                },
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_1"},
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/2",
                },
                "internal_info": {},
            }
        )
        self.trunk = utils.create_mock_object(
            {
                "id": "trunk_uuid",
                "name": "trunk",
                "port_id": "neutron_port_uuid_1",
                "sub_ports": [
                    {
                        "port_id": "neutron_port_uuid_2",
                        "segmentation_id": "222",
                        "segmentation_type": "vlan",
                    },
                    {
                        "port_id": "neutron_port_uuid_3",
                        "segmentation_id": "333",
                        "segmentation_type": "vlan",
                    },
                ],
            }
        )

    def test_take_action(self):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.find_trunk.return_value = self.trunk

        arglist = ["switch1", "Ethernet1/1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.find_trunk.assert_called_once_with(
            "switch1-Ethernet1/1"
        )
        self.app.client_manager.baremetal.node.vif_detach.assert_called_once_with(
            "11111111-2222-3333-4444-aaaaaaaaaaaa", "neutron_port_uuid_1"
        )
        self.app.client_manager.network.delete_trunk.assert_called_once_with(
            "trunk_uuid"
        )
        self.assertEqual(self.app.client_manager.network.delete_port.call_count, 3)

    def test_take_action_unknown_switchport(self):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]

        arglist = ["switch1", "Ethernet1/3"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.find_trunk.assert_not_called
        self.app.client_manager.baremetal.node.vif_detach.assert_not_called
        self.app.client_manager.network.delete_trunk.assert_not_called
        self.app.client_manager.network.delete_port.assert_not_called

    def test_take_action_unknown_switch(self):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]

        arglist = ["switch2", "Ethernet1/1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.find_trunk.assert_not_called
        self.app.client_manager.baremetal.node.vif_detach.assert_not_called
        self.app.client_manager.network.delete_trunk.assert_not_called
        self.app.client_manager.network.delete_port.assert_not_called

    def test_take_action_no_trunk(self):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.find_trunk.return_value = None

        arglist = ["switch1", "Ethernet1/1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no trunk named switch1-Ethernet1/1",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.find_trunk.assert_called_once_with(
            "switch1-Ethernet1/1"
        )
        self.app.client_manager.baremetal.node.vif_detach.assert_not_called
        self.app.client_manager.network.delete_trunk.assert_not_called
        self.app.client_manager.network.delete_port.assert_not_called


class TestAddTrunkVLAN(base.TestCommand):
    def setUp(self):
        super(TestAddTrunkVLAN, self).setUp()
        self.cmd = switch.AddTrunkVLAN(self.app, None)

        self.node = utils.create_mock_object(
            {
                "uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "name": "node1",
            }
        )
        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/1",
                },
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/2",
                },
            }
        )
        self.network = utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "network_type": "vlan",
                "provider_segmentation_id": "100",
                "subnet_ids": ["subnet_uuid"],
            }
        )
        self.neutron_port = utils.create_mock_object(
            {
                "id": "neutron_port_uuid",
                "network_id": "network_uuid",
                "name": "node1-port",
                "mac_address": "bb:bb:bb:bb:bb:bb",
                "fixed_ips": [{"ip_address": "2.2.2.2"}],
                "trunk_details": None,
            }
        )
        self.neutron_subport = utils.create_mock_object(
            {
                "id": "neutron_subport_uuid",
                "network_id": "network_uuid",
                "name": "node1-sub-port",
                "mac_address": "cc:cc:cc:cc:cc:cc",
                "fixed_ips": [{"ip_address": "3.3.3.3"}],
                "trunk_details": None,
            }
        )
        self.trunk = utils.create_mock_object(
            {
                "id": "trunk_uuid",
                "name": "trunk",
                "port_id": "neutron_port_uuid",
            }
        )

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.network.networks.return_value = [self.network]
        self.app.client_manager.network.find_trunk.return_value = self.trunk
        mock_gpn.return_value = "node1-port-trunk-port-sub-port"
        mock_gocp.return_value = self.neutron_subport

        arglist = ["switch1", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.baremetal.node.get.assert_called_once_with(
            "11111111-2222-3333-4444-aaaaaaaaaaaa"
        )
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="100"
        )
        self.app.client_manager.network.find_trunk.assert_called_once_with(
            "switch1-Ethernet1/1"
        )
        mock_gpn.assert_called_once_with(
            "test_network", prefix="switch1-Ethernet1/1", suffix="sub-port"
        )
        mock_gocp.assert_called_once_with(
            "node1-port-trunk-port-sub-port",
            self.network,
            self.app.client_manager.network,
        )
        self.app.client_manager.network.add_trunk_subports.assert_called_once_with(
            "trunk_uuid",
            [
                {
                    "port_id": "neutron_subport_uuid",
                    "segmentation_type": "vlan",
                    "segmentation_id": "100",
                }
            ],
        )

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_vlan(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = []

        arglist = ["switch1", "Ethernet1/1", "200"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: VLAN ID unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="200"
        )
        self.app.client_manager.network.find_trunk.assert_not_called
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called
        self.app.client_manager.network.add_trunk_subports.assert_not_called

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_switchport(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = [self.network]

        arglist = ["switch1", "Ethernet1/3", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_not_called
        self.app.client_manager.network.find_trunk.assert_not_called
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called
        self.app.client_manager.network.add_trunk_subports.assert_not_called

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_switch(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = [self.network]

        arglist = ["switch2", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_not_called
        self.app.client_manager.network.find_trunk.assert_not_called
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called
        self.app.client_manager.network.add_trunk_subports.assert_not_called

    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_no_trunk(self, mock_gpn, mock_gocp):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.network.networks.return_value = [self.network]
        self.app.client_manager.network.find_trunk.return_value = None

        arglist = ["switch1", "Ethernet1/1", "200"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no trunk named switch1-Ethernet1/1",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="200"
        )
        self.app.client_manager.network.find_trunk.assert_called_once_with(
            "switch1-Ethernet1/1"
        )
        mock_gpn.assert_not_called
        mock_gocp.assert_not_called
        self.app.client_manager.network.add_trunk_subports.assert_not_called


class TestRemoveTrunkVLAN(base.TestCommand):
    def setUp(self):
        super(TestRemoveTrunkVLAN, self).setUp()
        self.cmd = switch.RemoveTrunkVLAN(self.app, None)

        self.node = utils.create_mock_object(
            {
                "uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "name": "node1",
            }
        )
        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/1",
                },
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
                "local_link_connection": {
                    "switch_info": "switch1",
                    "port_id": "Ethernet1/2",
                },
            }
        )
        self.network = utils.create_mock_object(
            {
                "id": "network_uuid",
                "name": "test_network",
                "network_type": "vlan",
                "provider_segmentation_id": "100",
                "subnet_ids": ["subnet_uuid"],
            }
        )
        self.neutron_port = utils.create_mock_object(
            {
                "id": "neutron_port_uuid",
                "network_id": "network_uuid",
                "name": "node1-port",
                "mac_address": "bb:bb:bb:bb:bb:bb",
                "fixed_ips": [{"ip_address": "2.2.2.2"}],
                "trunk_details": None,
            }
        )
        self.neutron_subport = utils.create_mock_object(
            {
                "id": "neutron_subport_uuid",
                "network_id": "network_uuid",
                "name": "node1-sub-port",
                "mac_address": "cc:cc:cc:cc:cc:cc",
                "fixed_ips": [{"ip_address": "3.3.3.3"}],
                "trunk_details": None,
            }
        )
        self.trunk = utils.create_mock_object(
            {
                "id": "trunk_uuid",
                "name": "trunk",
                "port_id": "neutron_port_uuid",
            }
        )

    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action(self, mock_gpn):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.network.networks.return_value = [self.network]
        self.app.client_manager.network.find_trunk.return_value = self.trunk
        self.app.client_manager.network.find_port.return_value = self.neutron_subport
        mock_gpn.return_value = "node1-port-trunk-port-sub-port"

        arglist = ["switch1", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.baremetal.node.get.assert_called_once_with(
            "11111111-2222-3333-4444-aaaaaaaaaaaa"
        )
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="100"
        )
        self.app.client_manager.network.find_trunk.assert_called_once_with(
            "switch1-Ethernet1/1"
        )
        mock_gpn.assert_called_once_with(
            "test_network", prefix="switch1-Ethernet1/1", suffix="sub-port"
        )
        self.app.client_manager.network.find_port.assert_called_once_with(
            "node1-port-trunk-port-sub-port"
        )
        self.app.client_manager.network.delete_trunk_subports.assert_called_once_with(
            "trunk_uuid",
            [
                {
                    "port_id": "neutron_subport_uuid",
                }
            ],
        )

    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_vlan(self, mock_gpn):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = []

        arglist = ["switch1", "Ethernet1/1", "200"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: VLAN ID unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="200"
        )
        self.app.client_manager.network.find_trunk.assert_not_called
        mock_gpn.assert_not_called
        self.app.client_manager.network.find_port.assert_not_called
        self.app.client_manager.network.delete_trunk_subports.assert_not_called

    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_switchport(self, mock_gpn):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = [self.network]

        arglist = ["switch1", "Ethernet1/3", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_not_called
        self.app.client_manager.network.find_trunk.assert_not_called
        mock_gpn.assert_not_called
        self.app.client_manager.network.find_port.assert_not_called
        self.app.client_manager.network.delete_trunk_subports.assert_not_called

    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_unknown_switch(self, mock_gpn):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.network.networks.return_value = [self.network]

        arglist = ["switch2", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Switchport unknown",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_not_called
        self.app.client_manager.network.find_trunk.assert_not_called
        mock_gpn.assert_not_called
        self.app.client_manager.network.find_port.assert_not_called
        self.app.client_manager.network.delete_trunk_subports.assert_not_called

    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_no_trunk(self, mock_gpn):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.network.networks.return_value = [self.network]
        self.app.client_manager.network.find_trunk.return_value = None

        arglist = ["switch1", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: no trunk named switch1-Ethernet1/1",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="100"
        )
        self.app.client_manager.network.find_trunk.assert_called_once_with(
            "switch1-Ethernet1/1"
        )
        mock_gpn.assert_not_called
        self.app.client_manager.network.find_port.assert_not_called
        self.app.client_manager.network.delete_trunk_subports.assert_not_called

    @mock.patch("esiclient.utils.get_port_name", autospec=True)
    def test_take_action_no_trunk_port(self, mock_gpn):
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.network.networks.return_value = [self.network]
        self.app.client_manager.network.find_trunk.return_value = self.trunk
        self.app.client_manager.network.find_port.return_value = None
        mock_gpn.return_value = "node1-port-trunk-port-sub-port"

        arglist = ["switch1", "Ethernet1/1", "100"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: trunk is not attached to test_network",
            self.cmd.take_action,
            parsed_args,
        )

        self.app.client_manager.baremetal.port.list.assert_called_once_with(detail=True)
        self.app.client_manager.network.networks.assert_called_once_with(
            provider_network_type="vlan", provider_segmentation_id="100"
        )
        self.app.client_manager.network.find_trunk.assert_called_once_with(
            "switch1-Ethernet1/1"
        )
        mock_gpn.assert_called_once_with(
            "test_network", prefix="switch1-Ethernet1/1", suffix="sub-port"
        )
        self.app.client_manager.network.find_port.assert_called_once_with(
            "node1-port-trunk-port-sub-port"
        )
        self.app.client_manager.network.delete_trunk_subports.assert_not_called

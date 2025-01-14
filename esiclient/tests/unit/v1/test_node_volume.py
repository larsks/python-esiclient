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
from esiclient.v1 import node_volume


class TestAttach(base.TestCommand):
    def setUp(self):
        super(TestAttach, self).setUp()
        self.cmd = node_volume.Attach(self.app, None)

        self.port1 = utils.create_mock_object(
            {
                "uuid": "port_uuid_1",
                "node_uuid": "node_uuid_1",
                "address": "aa:aa:aa:aa:aa:aa",
                "internal_info": {"tenant_vif_port_id": "neutron_port_uuid_1"},
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "uuid": "port_uuid_2",
                "node_uuid": "node_uuid_1",
                "address": "bb:bb:bb:bb:bb:bb",
                "internal_info": {},
            }
        )
        self.node = utils.create_mock_object(
            {"uuid": "node_uuid_1", "name": "node1", "provision_state": "available"}
        )
        self.node_active = utils.create_mock_object(
            {"uuid": "node_uuid_1", "name": "node1", "provision_state": "active"}
        )
        self.volume_connector = utils.create_mock_object(
            {
                "uuid": "vc_uuid",
            }
        )
        self.volume_target = utils.create_mock_object(
            {"uuid": "vt_uuid", "volume_id": "volume_uuid_1"}
        )
        self.volume = utils.create_mock_object(
            {"id": "volume_uuid_1", "name": "volume1", "status": "available"}
        )
        self.volume_in_use = utils.create_mock_object(
            {"id": "volume_uuid_1", "name": "volume1", "status": "in-use"}
        )
        self.network = utils.create_mock_object(
            {"id": "network_uuid", "name": "test_network"}
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

        self.app.client_manager.network.find_network.return_value = self.network
        self.app.client_manager.network.get_network.return_value = self.network
        self.app.client_manager.network.create_port.return_value = self.neutron_port
        self.app.client_manager.network.find_port.return_value = self.neutron_port
        self.app.client_manager.network.ports.return_value = []
        self.app.client_manager.baremetal.node.set_provision_state.return_value = (
            self.node
        )
        self.app.client_manager.baremetal.volume.volume_connector.create.return_value = None
        self.app.client_manager.baremetal.volume.volume_connector.delete.return_value = None
        self.app.client_manager.baremetal.volume.volume_target.create.return_value = (
            None
        )

    @mock.patch("oslo_utils.uuidutils.is_uuid_like", return_value=False, autospec=True)
    def test_take_action(self, mock_iul):
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.baremetal.node.update.return_value = self.node
        self.app.client_manager.baremetal.volume_connector.list.return_value = []
        self.app.client_manager.baremetal.volume_target.list.return_value = []
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.volume.volumes.find.return_value = self.volume

        arglist = ["node1", "volume_uuid_1", "--network", "test_network"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (["Node", "Volume"], ["node1", "volume1"])
        self.assertEqual(expected, results)
        self.app.client_manager.network.find_network.assert_called_once_with(
            "test_network"
        )
        self.app.client_manager.baremetal.node.get.assert_called_once_with("node1")
        mock_iul.assert_called_once_with("volume_uuid_1")
        self.app.client_manager.volume.volumes.find.assert_called_once_with(
            name="volume_uuid_1"
        )
        self.app.client_manager.baremetal.port.list.assert_called_once_with(
            node="node1", detail=True
        )
        self.app.client_manager.baremetal.node.update.assert_called_once()
        self.app.client_manager.baremetal.volume_connector.list.assert_called_once_with(
            node="node1"
        )
        self.app.client_manager.baremetal.volume_connector.create.assert_called_once()
        self.app.client_manager.baremetal.volume_target.list.assert_called_once_with(
            node="node1", fields=["volume_id"]
        )
        self.app.client_manager.baremetal.volume_target.create.assert_called_once()
        self.app.client_manager.network.create_port.assert_called_once_with(
            name="esi-node1-test_network-volume",
            network_id=self.network.id,
            device_owner="baremetal:none",
        )
        self.app.client_manager.baremetal.node.vif_attach.assert_called_once_with(
            "node1", self.neutron_port.id
        )
        self.app.client_manager.baremetal.node.set_provision_state.assert_called_once_with(
            "node1", "active"
        )

    @mock.patch("oslo_utils.uuidutils.is_uuid_like", return_value=True, autospec=True)
    def test_take_action_volume_uuid(self, mock_iul):
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.baremetal.node.update.return_value = self.node
        self.app.client_manager.baremetal.volume_connector.list.return_value = []
        self.app.client_manager.baremetal.volume_target.list.return_value = []
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.volume.volumes.get.return_value = self.volume

        arglist = ["node1", "volume_uuid_1", "--network", "test_network"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (["Node", "Volume"], ["node1", "volume1"])
        self.assertEqual(expected, results)
        self.app.client_manager.network.find_network.assert_called_once_with(
            "test_network"
        )
        self.app.client_manager.baremetal.node.get.assert_called_once_with("node1")
        mock_iul.assert_called_once_with("volume_uuid_1")
        self.app.client_manager.volume.volumes.get.assert_called_once_with(
            "volume_uuid_1"
        )
        self.app.client_manager.baremetal.port.list.assert_called_once_with(
            node="node1", detail=True
        )
        self.app.client_manager.baremetal.node.update.assert_called_once()
        self.app.client_manager.baremetal.volume_connector.list.assert_called_once_with(
            node="node1"
        )
        self.app.client_manager.baremetal.volume_connector.create.assert_called_once()
        self.app.client_manager.baremetal.volume_target.list.assert_called_once_with(
            node="node1", fields=["volume_id"]
        )
        self.app.client_manager.baremetal.volume_target.create.assert_called_once()
        self.app.client_manager.network.create_port.assert_called_once_with(
            name="esi-node1-test_network-volume",
            network_id=self.network.id,
            device_owner="baremetal:none",
        )
        self.app.client_manager.baremetal.node.vif_attach.assert_called_once_with(
            "node1", self.neutron_port.id
        )
        self.app.client_manager.baremetal.node.set_provision_state.assert_called_once_with(
            "node1", "active"
        )

    def test_take_action_port_and_network_exception(self):
        arglist = [
            "node1",
            "volume_uuid_1",
            "--network",
            "test_network",
            "--port",
            "neutron_port_uuid",
        ]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Specify only one of network or port",
            self.cmd.take_action,
            parsed_args,
        )

    def test_take_action_no_port_or_network_exception(self):
        arglist = ["node1", "volume_uuid_1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: You must specify either network or port",
            self.cmd.take_action,
            parsed_args,
        )

    @mock.patch("oslo_utils.uuidutils.is_uuid_like", return_value=False, autospec=True)
    def test_take_action_port(self, mock_iul):
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.baremetal.node.update.return_value = self.node
        self.app.client_manager.baremetal.volume_connector.list.return_value = []
        self.app.client_manager.baremetal.volume_target.list.return_value = []
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.volume.volumes.find.return_value = self.volume

        arglist = ["node1", "volume_uuid_1", "--port", "neutron_port_uuid"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (["Node", "Volume"], ["node1", "volume1"])
        self.assertEqual(expected, results)
        self.app.client_manager.network.find_port.assert_called_once_with(
            "neutron_port_uuid"
        )
        self.app.client_manager.baremetal.node.get.assert_called_once_with("node1")
        mock_iul.assert_called_once_with("volume_uuid_1")
        self.app.client_manager.volume.volumes.find.assert_called_once_with(
            name="volume_uuid_1"
        )
        self.app.client_manager.baremetal.port.list.assert_called_once_with(
            node="node1", detail=True
        )
        self.app.client_manager.baremetal.node.update.assert_called_once()
        self.app.client_manager.baremetal.volume_connector.list.assert_called_once_with(
            node="node1"
        )
        self.app.client_manager.baremetal.volume_connector.create.assert_called_once()
        self.app.client_manager.baremetal.volume_target.list.assert_called_once_with(
            node="node1", fields=["volume_id"]
        )
        self.app.client_manager.baremetal.volume_target.create.assert_called_once()
        self.app.client_manager.network.create_port.assert_not_called()
        self.app.client_manager.baremetal.node.vif_attach.assert_called_once_with(
            "node1", self.neutron_port.id
        )
        self.app.client_manager.baremetal.node.set_provision_state.assert_called_once_with(
            "node1", "active"
        )

    @mock.patch("oslo_utils.uuidutils.is_uuid_like", return_value=False, autospec=True)
    def test_take_action_node_active(self, mock_iul):
        self.app.client_manager.baremetal.node.get.return_value = self.node_active

        arglist = ["node1", "volume_uuid_1", "--network", "test_network"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Node node1 must be in the available state",
            self.cmd.take_action,
            parsed_args,
        )
        self.app.client_manager.network.find_network.assert_called_once_with(
            "test_network"
        )
        self.app.client_manager.baremetal.node.get.assert_called_once_with("node1")
        mock_iul.assert_called_once_with("volume_uuid_1")
        self.app.client_manager.volume.volumes.find.assert_called_once_with(
            name="volume_uuid_1"
        )

    @mock.patch("oslo_utils.uuidutils.is_uuid_like", return_value=False, autospec=True)
    def test_take_action_volume_in_use(self, mock_iul):
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.volume.volumes.find.return_value = self.volume_in_use

        arglist = ["node1", "volume_uuid_1", "--network", "test_network"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Volume volume1 must be in the available state",
            self.cmd.take_action,
            parsed_args,
        )
        self.app.client_manager.network.find_network.assert_called_once_with(
            "test_network"
        )
        self.app.client_manager.baremetal.node.get.assert_called_once_with("node1")
        mock_iul.assert_called_once_with("volume_uuid_1")
        self.app.client_manager.volume.volumes.find.assert_called_once_with(
            name="volume_uuid_1"
        )

    @mock.patch("oslo_utils.uuidutils.is_uuid_like", return_value=False, autospec=True)
    def test_take_action_no_baremetal_ports(self, mock_iul):
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.volume.volumes.find.return_value = self.volume
        self.app.client_manager.baremetal.port.list.return_value = [self.port1]

        arglist = ["node1", "volume_uuid_1", "--network", "test_network"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: Node node1 has no free ports",
            self.cmd.take_action,
            parsed_args,
        )
        self.app.client_manager.network.find_network.assert_called_once_with(
            "test_network"
        )
        self.app.client_manager.baremetal.node.get.assert_called_once_with("node1")
        mock_iul.assert_called_once_with("volume_uuid_1")
        self.app.client_manager.volume.volumes.find.assert_called_once_with(
            name="volume_uuid_1"
        )
        self.app.client_manager.baremetal.port.list.assert_called_once_with(
            node="node1", detail=True
        )

    @mock.patch("oslo_utils.uuidutils.is_uuid_like", return_value=False, autospec=True)
    def test_take_action_volume_connector_exists(self, mock_iul):
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.baremetal.node.update.return_value = self.node
        self.app.client_manager.baremetal.volume_connector.list.return_value = [
            self.volume_connector
        ]
        self.app.client_manager.baremetal.volume_target.list.return_value = []
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.volume.volumes.find.return_value = self.volume

        arglist = ["node1", "volume_uuid_1", "--network", "test_network"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (["Node", "Volume"], ["node1", "volume1"])
        self.assertEqual(expected, results)
        self.app.client_manager.network.find_network.assert_called_once_with(
            "test_network"
        )
        self.app.client_manager.baremetal.node.get.assert_called_once_with("node1")
        mock_iul.assert_called_once_with("volume_uuid_1")
        self.app.client_manager.volume.volumes.find.assert_called_once_with(
            name="volume_uuid_1"
        )
        self.app.client_manager.baremetal.port.list.assert_called_once_with(
            node="node1", detail=True
        )
        self.app.client_manager.baremetal.node.update.assert_called_once()
        self.app.client_manager.baremetal.volume_connector.list.assert_called_once_with(
            node="node1"
        )
        self.app.client_manager.baremetal.volume_connector.delete.assert_called_once()
        self.app.client_manager.baremetal.volume_connector.create.assert_called_once()
        self.app.client_manager.baremetal.volume_target.list.assert_called_once_with(
            node="node1", fields=["volume_id"]
        )
        self.app.client_manager.baremetal.volume_target.create.assert_called_once()
        self.app.client_manager.network.create_port.assert_called_once_with(
            name="esi-node1-test_network-volume",
            network_id=self.network.id,
            device_owner="baremetal:none",
        )
        self.app.client_manager.baremetal.node.vif_attach.assert_called_once_with(
            "node1", self.neutron_port.id
        )
        self.app.client_manager.baremetal.node.set_provision_state.assert_called_once_with(
            "node1", "active"
        )

    @mock.patch("oslo_utils.uuidutils.is_uuid_like", return_value=False, autospec=True)
    def test_take_action_volume_target_exists(self, mock_iul):
        self.app.client_manager.baremetal.node.get.return_value = self.node
        self.app.client_manager.baremetal.node.update.return_value = self.node
        self.app.client_manager.baremetal.volume_connector.list.return_value = []
        self.app.client_manager.baremetal.volume_target.list.return_value = [
            self.volume_target
        ]
        self.app.client_manager.baremetal.port.list.return_value = [
            self.port1,
            self.port2,
        ]
        self.app.client_manager.volume.volumes.find.return_value = self.volume

        arglist = ["node1", "volume_uuid_1", "--network", "test_network"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (["Node", "Volume"], ["node1", "volume1"])
        self.assertEqual(expected, results)
        self.app.client_manager.network.find_network.assert_called_once_with(
            "test_network"
        )
        self.app.client_manager.baremetal.node.get.assert_called_once_with("node1")
        mock_iul.assert_called_once_with("volume_uuid_1")
        self.app.client_manager.volume.volumes.find.assert_called_once_with(
            name="volume_uuid_1"
        )
        self.app.client_manager.baremetal.port.list.assert_called_once_with(
            node="node1", detail=True
        )
        self.app.client_manager.baremetal.node.update.assert_called_once()
        self.app.client_manager.baremetal.volume_connector.list.assert_called_once_with(
            node="node1"
        )
        self.app.client_manager.baremetal.volume_connector.create.assert_called_once()
        self.app.client_manager.baremetal.volume_target.list.assert_called_once_with(
            node="node1", fields=["volume_id"]
        )
        self.app.client_manager.baremetal.volume_target.create.assert_not_called()
        self.app.client_manager.network.create_port.assert_called_once_with(
            name="esi-node1-test_network-volume",
            network_id=self.network.id,
            device_owner="baremetal:none",
        )
        self.app.client_manager.baremetal.node.vif_attach.assert_called_once_with(
            "node1", self.neutron_port.id
        )
        self.app.client_manager.baremetal.node.set_provision_state.assert_called_once_with(
            "node1", "active"
        )

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

import mock
from unittest import TestCase

from esiclient.tests.unit import utils
from esiclient.v1.cluster import utils as cluster_utils


class TestSetNodeClusterInfo(TestCase):
    def setUp(self):
        super(TestSetNodeClusterInfo, self).setUp()
        self.ironic_client = mock.Mock()
        self.ironic_client.node.update.return_value = None

    def test_set_node_cluster_info(self):
        cluster_dict = {
            cluster_utils.ESI_CLUSTER_UUID: "cluster-uuid",
            cluster_utils.ESI_PORT_UUID: "port-uuid",
            cluster_utils.ESI_FIP_UUID: "fip-uuid",
        }
        cluster_utils.set_node_cluster_info(
            self.ironic_client, "node_uuid", cluster_dict
        )
        self.ironic_client.node.update.assert_called_once_with(
            "node_uuid",
            [
                {
                    "path": "/extra/esi_cluster_uuid",
                    "value": "cluster-uuid",
                    "op": "add",
                },
                {"path": "/extra/esi_port_uuid", "value": "port-uuid", "op": "add"},
                {"path": "/extra/esi_fip_uuid", "value": "fip-uuid", "op": "add"},
            ],
        )


class TestCleanClusterNode(TestCase):
    def setUp(self):
        super(TestCleanClusterNode, self).setUp()

        self.node1 = utils.create_mock_object(
            {
                "uuid": "node_uuid_1",
                "name": "node1",
                "extra": {
                    "esi_cluster_uuid": "cluster-uuid-1",
                    "esi_trunk_uuid": "trunk-uuid-1",
                    "esi_fip_uuid": "fip-uuid-1",
                },
            }
        )
        self.node2 = utils.create_mock_object(
            {
                "uuid": "node_uuid_2",
                "name": "node2",
                "extra": {
                    "esi_cluster_uuid": "cluster-uuid-1",
                    "esi_port_uuid": "port-uuid-2",
                },
            }
        )
        self.trunk = utils.create_mock_object(
            {
                "id": "trunk_uuid_1",
                "name": "trunk",
            }
        )

        self.ironic_client = mock.Mock()
        self.neutron_client = mock.Mock()
        self.neutron_client.find_trunk.return_value = self.trunk

    def test_clean_cluster_node(self):
        cluster_utils.clean_cluster_node(
            self.ironic_client, self.neutron_client, self.node2
        )
        self.ironic_client.node.set_provision_state.assert_called_once_with(
            "node_uuid_2", "deleted"
        )
        self.neutron_client.delete_port.assert_called_once_with("port-uuid-2")
        self.ironic_client.node.update.assert_called_once_with(
            "node_uuid_2",
            [
                {"path": "/extra/esi_cluster_uuid", "op": "remove"},
                {"path": "/extra/esi_port_uuid", "op": "remove"},
            ],
        )

    @mock.patch("esiclient.utils.delete_trunk", autospec=True)
    def test_clean_cluster_node_trunk(self, mock_dt):
        cluster_utils.clean_cluster_node(
            self.ironic_client, self.neutron_client, self.node1
        )
        self.ironic_client.node.set_provision_state.assert_called_once_with(
            "node_uuid_1", "deleted"
        )
        self.neutron_client.find_trunk.assert_called_once_with("trunk-uuid-1")
        mock_dt.assert_called_once_with(self.neutron_client, self.trunk)
        self.neutron_client.delete_ip.assert_called_once_with("fip-uuid-1")
        self.ironic_client.node.update.assert_called_once_with(
            "node_uuid_1",
            [
                {"path": "/extra/esi_cluster_uuid", "op": "remove"},
                {"path": "/extra/esi_trunk_uuid", "op": "remove"},
                {"path": "/extra/esi_fip_uuid", "op": "remove"},
            ],
        )

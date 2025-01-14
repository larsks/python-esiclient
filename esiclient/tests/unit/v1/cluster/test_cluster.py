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
from mock import call
from mock import patch

from esiclient.tests.unit import base
from esiclient.tests.unit import utils
from esiclient.v1.cluster import cluster
from esiclient.v1.cluster import utils as cluster_utils


class TestList(base.TestCommand):
    def setUp(self):
        super(TestList, self).setUp()
        self.cmd = cluster.List(self.app, None)

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
        self.node3 = utils.create_mock_object(
            {
                "uuid": "node_uuid_3",
                "name": "node3",
                "extra": {
                    "esi_cluster_uuid": "cluster-uuid-1",
                    "esi_port_uuid": "port-uuid-3",
                },
            }
        )
        self.node4 = utils.create_mock_object(
            {
                "uuid": "node_uuid_4",
                "name": "node4",
                "extra": {
                    "esi_cluster_uuid": "cluster-uuid-2",
                    "esi_trunk_uuid": "trunk-uuid-2",
                    "esi_fip_uuid": "fip-uuid-2",
                },
            }
        )
        self.node5 = utils.create_mock_object(
            {"uuid": "node_uuid_5", "name": "node5", "extra": {}}
        )
        self.trunk = utils.create_mock_object(
            {
                "id": "trunk_uuid_1",
                "name": "trunk",
            }
        )

        self.app.client_manager.baremetal.node.list.return_value = [
            self.node1,
            self.node2,
            self.node3,
            self.node4,
        ]

    def test_take_action(self):
        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            ["Cluster", "Node", "Associated"],
            [
                [
                    "cluster-uuid-1",
                    "node1\nnode2\nnode3",
                    "{'esi_trunk_uuid': 'trunk-uuid-1', "
                    "'esi_fip_uuid': 'fip-uuid-1'}\n"
                    "{'esi_port_uuid': 'port-uuid-2'}\n"
                    "{'esi_port_uuid': 'port-uuid-3'}",
                ],
                [
                    "cluster-uuid-2",
                    "node4",
                    "{'esi_trunk_uuid': 'trunk-uuid-2', 'esi_fip_uuid': 'fip-uuid-2'}",
                ],
            ],
        )
        self.assertEqual(expected, results)
        self.app.client_manager.baremetal.node.list.assert_called_once_with(
            fields=["uuid", "name", "extra"],
        )


class TestOrchestrate(base.TestCommand):
    def setUp(self):
        super(TestOrchestrate, self).setUp()
        self.cmd = cluster.Orchestrate(self.app, None)

        self.node1 = utils.create_mock_object(
            {
                "uuid": "node_uuid_1",
                "name": "node1",
                "provision_state": "available",
                "resource_class": "baremetal",
            }
        )
        self.node2 = utils.create_mock_object(
            {
                "uuid": "node_uuid_2",
                "name": "node2",
                "provision_state": "available",
                "resource_class": "baremetal",
            }
        )
        self.node3 = utils.create_mock_object(
            {
                "uuid": "node_uuid_3",
                "name": "node3",
                "provision_state": "available",
                "resource_class": "baremetal",
            }
        )
        self.port1 = utils.create_mock_object(
            {
                "id": "port_uuid_1",
                "name": "port1",
                "network_id": "network_uuid_1",
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "id": "port_uuid_2",
                "name": "port2",
                "network_id": "network_uuid_1",
            }
        )
        self.port3 = utils.create_mock_object(
            {
                "id": "port_uuid_3",
                "name": "port3",
                "network_id": "network_uuid_1",
            }
        )
        self.private_network = utils.create_mock_object(
            {
                "id": "network_uuid_1",
                "name": "private_network_1",
            }
        )
        self.external_network = utils.create_mock_object(
            {
                "id": "network_uuid_3",
                "name": "external_network",
            }
        )
        self.fip = utils.create_mock_object(
            {
                "id": "fip_uuid_1",
            }
        )
        self.image = utils.create_mock_object(
            {
                "id": "image_uuid_1",
                "name": "image",
            }
        )

        def mock_find_network(name):
            if name == "private_network_1":
                return self.private_network
            if name == "external_network":
                return self.external_network
            return None

        self.app.client_manager.network.find_network.side_effect = mock_find_network
        self.app.client_manager.baremetal.node.list.return_value = [
            self.node1,
            self.node2,
            self.node3,
        ]
        self.app.client_manager.network.ips.return_value = []
        self.app.client_manager.network.networks.return_value = []
        self.app.client_manager.network.find_port.return_value = self.port1
        self.app.client_manager.image.find_image.return_value = self.image

    @mock.patch("esiclient.v1.cluster.utils.set_node_cluster_info", autospec=True)
    @mock.patch("esiclient.utils.get_floating_ip", autospec=True)
    @mock.patch("esiclient.utils.get_full_network_info_from_port", autospec=True)
    @mock.patch("esiclient.utils.get_or_assign_port_floating_ip", autospec=True)
    @mock.patch("esiclient.utils.boot_node_from_url", autospec=True)
    @mock.patch("esiclient.utils.provision_node_with_image", autospec=True)
    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.create_trunk", autospec=True)
    @mock.patch("oslo_utils.uuidutils.generate_uuid", autospec=True)
    @mock.patch("json.load", autospec=True)
    def test_take_action(
        self,
        mock_load,
        mock_uuid,
        mock_ct,
        mock_gocp,
        mock_pnwi,
        mock_bnfu,
        mock_goapfi,
        mock_gfnifp,
        mock_gfi,
        mock_snci,
    ):
        mock_load.return_value = {
            "node_configs": [
                {
                    "nodes": {"node_uuids": ["node1"]},
                    "network": {
                        "network_uuid": "private_network_1",
                        "tagged_network_uuids": ["private_network_2"],
                        "fip_network_uuid": "external_network",
                    },
                    "provisioning": {
                        "provisioning_type": "image",
                        "image_uuid": "image_uuid",
                        "ssh_key": "/path/to/ssh/key",
                    },
                },
                {
                    "nodes": {"num_nodes": "2", "resource_class": "baremetal"},
                    "network": {"network_uuid": "private_network_1"},
                    "provisioning": {
                        "provisioning_type": "image_url",
                        "url": "https://image.url",
                    },
                },
            ]
        }
        mock_goapfi.return_value = self.fip
        mock_uuid.return_value = "cluster-uuid"
        mock_ct.return_value = None, self.port1
        mock_gocp.side_effect = [self.port2, self.port3]
        mock_gfnifp.return_value = [], [], []
        mock_gfi.return_value = [], []

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            self.cmd.take_action(parsed_args)

        self.app.client_manager.baremetal.node.list.assert_called_once_with(
            fields=["uuid", "name", "resource_class"], provision_state="available"
        )
        mock_uuid.assert_called_once
        self.app.client_manager.network.find_network.assert_has_calls(
            [call("private_network_1"), call("external_network")]
        )
        mock_ct.assert_called_once_with(
            self.app.client_manager.network,
            "esi-node1-trunk",
            self.private_network,
            ["private_network_2"],
        )
        self.app.client_manager.network.find_port.assert_called_once_with(self.port1.id)
        mock_gocp.assert_has_calls(
            [
                call(
                    "esi-node2-private_network_1",
                    self.private_network,
                    self.app.client_manager.network,
                ),
                call(
                    "esi-node3-private_network_1",
                    self.private_network,
                    self.app.client_manager.network,
                ),
            ]
        )
        mock_pnwi.assert_called_once_with(
            self.node1.uuid,
            "baremetal",
            self.port1.id,
            self.image.id,
            "/path/to/ssh/key",
        )
        mock_bnfu.assert_has_calls(
            [
                call(
                    self.node2.uuid,
                    "https://image.url",
                    self.port2.id,
                    self.app.client_manager.baremetal,
                ),
                call(
                    self.node3.uuid,
                    "https://image.url",
                    self.port3.id,
                    self.app.client_manager.baremetal,
                ),
            ]
        )
        mock_goapfi.assert_called_once_with(
            self.port1, self.external_network, self.app.client_manager.network
        )
        assert mock_gfnifp.call_count == 3
        assert mock_gfi.call_count == 3
        mock_snci.assert_has_calls(
            [
                call(
                    self.app.client_manager.baremetal,
                    "node_uuid_1",
                    {
                        cluster_utils.ESI_CLUSTER_UUID: "cluster-uuid",
                        cluster_utils.ESI_PORT_UUID: "port_uuid_1",
                        cluster_utils.ESI_FIP_UUID: "fip_uuid_1",
                    },
                ),
                call(
                    self.app.client_manager.baremetal,
                    "node_uuid_2",
                    {
                        cluster_utils.ESI_CLUSTER_UUID: "cluster-uuid",
                        cluster_utils.ESI_PORT_UUID: "port_uuid_2",
                    },
                ),
                call(
                    self.app.client_manager.baremetal,
                    "node_uuid_3",
                    {
                        cluster_utils.ESI_CLUSTER_UUID: "cluster-uuid",
                        cluster_utils.ESI_PORT_UUID: "port_uuid_3",
                    },
                ),
            ]
        )

    @mock.patch("json.load", autospec=True)
    def test_take_action_insufficient_nodes(self, mock_load):
        mock_load.return_value = {
            "node_configs": [
                {
                    "nodes": {"node_uuids": ["node1"]},
                    "network": {
                        "network_uuid": "private_network_1",
                        "tagged_network_uuids": ["private_network_2"],
                        "fip_network_uuid": "external_network",
                    },
                    "provisioning": {
                        "provisioning_type": "image",
                        "image_uuid": "image_uuid",
                        "ssh_key": "/path/to/ssh/key",
                    },
                },
                {
                    "nodes": {"num_nodes": "3", "resource_class": "baremetal"},
                    "network": {"network_uuid": "private_network_1"},
                    "provisioning": {
                        "provisioning_type": "image_url",
                        "url": "https://image.url",
                    },
                },
            ]
        }

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            self.assertRaisesRegex(
                cluster_utils.ESIOrchestrationException,
                "Cannot find 3 free baremetal nodes",
                self.cmd.take_action,
                parsed_args,
            )

        self.app.client_manager.baremetal.node.list.assert_called_once_with(
            fields=["uuid", "name", "resource_class"], provision_state="available"
        )

    @mock.patch("json.load", autospec=True)
    def test_take_action_unavailable_node(self, mock_load):
        mock_load.return_value = {
            "node_configs": [
                {
                    "nodes": {"node_uuids": ["node5"]},
                    "network": {
                        "network_uuid": "private_network_1",
                        "tagged_network_uuids": ["private_network_2"],
                        "fip_network_uuid": "external_network",
                    },
                    "provisioning": {
                        "provisioning_type": "image",
                        "image_uuid": "image_uuid",
                        "ssh_key": "/path/to/ssh/key",
                    },
                },
                {
                    "nodes": {"num_nodes": "2", "resource_class": "baremetal"},
                    "network": {"network_uuid": "private_network_1"},
                    "provisioning": {
                        "provisioning_type": "image_url",
                        "url": "https://image.url",
                    },
                },
            ]
        }

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            self.assertRaisesRegex(
                cluster_utils.ESIOrchestrationException,
                "node5 is not an available node",
                self.cmd.take_action,
                parsed_args,
            )

        self.app.client_manager.baremetal.node.list.assert_called_once_with(
            fields=["uuid", "name", "resource_class"], provision_state="available"
        )

    @mock.patch("json.load", autospec=True)
    def test_take_action_no_network(self, mock_load):
        mock_load.return_value = {
            "node_configs": [
                {
                    "nodes": {"node_uuids": ["node1"]},
                    "network": {
                        "no_network": "",
                        "tagged_network_uuids": ["private_network_2"],
                        "fip_network_uuid": "external_network",
                    },
                    "provisioning": {
                        "provisioning_type": "image",
                        "image_uuid": "image_uuid",
                        "ssh_key": "/path/to/ssh/key",
                    },
                },
                {
                    "nodes": {"num_nodes": "2", "resource_class": "baremetal"},
                    "network": {"no_network": ""},
                    "provisioning": {
                        "provisioning_type": "image_url",
                        "url": "https://image.url",
                    },
                },
            ]
        }

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            self.assertRaisesRegex(
                cluster_utils.ESIOrchestrationException,
                "Must specify a network",
                self.cmd.take_action,
                parsed_args,
            )

        self.app.client_manager.baremetal.node.list.assert_called_once_with(
            fields=["uuid", "name", "resource_class"], provision_state="available"
        )

    @mock.patch("json.load", autospec=True)
    def test_take_action_invalid_provisioning_type(self, mock_load):
        mock_load.return_value = {
            "node_configs": [
                {
                    "nodes": {"node_uuids": ["node1"]},
                    "network": {
                        "network_uuid": "private_network_1",
                        "tagged_network_uuids": ["private_network_2"],
                        "fip_network_uuid": "external_network",
                    },
                    "provisioning": {
                        "provisioning_type": "foo",
                        "image_uuid": "image_uuid",
                        "ssh_key": "/path/to/ssh/key",
                    },
                },
                {
                    "nodes": {"num_nodes": "2", "resource_class": "baremetal"},
                    "network": {"network_uuid": "private_network_1"},
                    "provisioning": {
                        "provisioning_type": "bar",
                        "url": "https://image.url",
                    },
                },
            ]
        }

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            self.assertRaisesRegex(
                cluster_utils.ESIOrchestrationException,
                "Unknown provisioning method",
                self.cmd.take_action,
                parsed_args,
            )

        self.app.client_manager.baremetal.node.list.assert_called_once_with(
            fields=["uuid", "name", "resource_class"], provision_state="available"
        )


class TestUndeploy(base.TestCommand):
    def setUp(self):
        super(TestUndeploy, self).setUp()
        self.cmd = cluster.Undeploy(self.app, None)

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
        self.node3 = utils.create_mock_object(
            {
                "uuid": "node_uuid_3",
                "name": "node3",
                "extra": {
                    "esi_cluster_uuid": "cluster-uuid-1",
                    "esi_port_uuid": "port-uuid-3",
                },
            }
        )
        self.node4 = utils.create_mock_object(
            {
                "uuid": "node_uuid_4",
                "name": "node4",
                "extra": {
                    "esi_cluster_uuid": "cluster-uuid-2",
                    "esi_trunk_uuid": "trunk-uuid-2",
                    "esi_fip_uuid": "fip-uuid-2",
                },
            }
        )
        self.node5 = utils.create_mock_object(
            {"uuid": "node_uuid_5", "name": "node5", "extra": {}}
        )

        self.app.client_manager.baremetal.node.list.return_value = [
            self.node1,
            self.node2,
            self.node3,
            self.node4,
        ]

    @mock.patch("esiclient.v1.cluster.utils.clean_cluster_node", autospec=True)
    def test_take_action(self, mock_ccn):
        arglist = ["cluster-uuid-1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        self.app.client_manager.baremetal.node.list.assert_called_once_with(
            fields=["uuid", "name", "extra"],
        )
        mock_ccn.assert_has_calls(
            [
                call(
                    self.app.client_manager.baremetal,
                    self.app.client_manager.network,
                    self.node1,
                ),
                call(
                    self.app.client_manager.baremetal,
                    self.app.client_manager.network,
                    self.node2,
                ),
                call(
                    self.app.client_manager.baremetal,
                    self.app.client_manager.network,
                    self.node3,
                ),
            ]
        )

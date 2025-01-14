#    Copyright (c) 2016 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import ddt
from tempest.lib import exceptions

from esiclient.tests.functional import base
from esiclient.tests.functional import utils


@ddt.ddt
class NodeNetworkTests(base.ESIBaseTestClass):
    """Functional tests for ESI node/network commands."""

    @classmethod
    def setUpClass(cls):
        super(NodeNetworkTests, cls).setUpClass()
        cls._init_dummy_project(cls, "project1", ["lessee", "member"])

    def setUp(self):
        super(NodeNetworkTests, self).setUp()
        self.clients = NodeNetworkTests.clients
        self.users = NodeNetworkTests.users
        self.projects = NodeNetworkTests.projects
        if "test_node_ident" not in NodeNetworkTests.config["functional"]:
            self.fail("test_node_ident must be specified in test config")
        self.node = NodeNetworkTests.config["functional"]["test_node_ident"]

    def test_admin_attach_and_detach(self):
        """Tests that an admin can attach and detach a network from a node

        Test steps:
        1) Admin retrieves information about the node.
        2) Admin sets provision state of the node to manageable.
        3) Admin creates a network.
        4) Admin creates a port on the network.
        5) Admin attaches node to network using port.
        6) Admin detaches node from network
        7) (cleanup) Delete the port created in step 5.
        8) (cleanup) Delete the network created in step 4.
        9) (cleanup) Undeploy the node.

        """

        node = utils.node_show(self.clients["admin"], self.node)
        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(self.clients["admin"], self.node, "manage")

        network = utils.network_create(self.clients["admin"])
        self.addCleanup(utils.network_delete, self.clients["admin"], network["name"])
        port = utils.port_create(self.clients["admin"], network["name"])
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        utils.esi_node_network_attach(self.clients["admin"], self.node, port["name"])

        node_network_list = utils.esi_node_network_list(
            self.clients["admin"], params="--node {0}".format(self.node)
        )

        self.assertEqual(
            node_network_list[0]["Network"],
            "{0} ({1})".format(network["name"], network["provider:segmentation_id"]),
        )

        utils.esi_node_network_detach(self.clients["admin"], self.node, port["name"])
        node_network_list = utils.esi_node_network_list(
            self.clients["admin"], params="--node {0}".format(self.node)
        )
        self.assertEqual(node_network_list[0]["Network"], None)

    def test_lessee_attach_and_detach(self):
        """Tests that lessee can attach/detach a network from a node

        Test steps:
        1) Admin sets lessee of node to User 1.
        2) User 1 retrieves information about the node.
        3) User 1 sets provision state of the node to manageable.
        4) User 1 creates a network.
        5) User 1 creates a port on the network.
        6) User 1 attaches node to network using port.
        7) User 1 detaches node from network
        8) (cleanup) Delete the port created in step 5.
        9) (cleanup) Delete the network created in step 4.
        10) (cleanup) Undeploy the node
        11) (cleanup) Reset the lessee of the node.

        """

        node = utils.node_show(self.clients["admin"], self.node)
        utils.node_set(
            self.clients["admin"], self.node, "lessee", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "lessee", node["lessee"]
        )

        node = utils.node_show(self.clients["project1-member"], self.node)
        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(
                self.clients["project1-member"], self.node, "manage"
            )

        network = utils.network_create(self.clients["project1-member"])
        self.addCleanup(utils.network_delete, self.clients["admin"], network["name"])
        port = utils.port_create(self.clients["project1-member"], network["name"])
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        utils.esi_node_network_attach(
            self.clients["project1-member"], self.node, port["name"]
        )

        node_network_list = utils.esi_node_network_list(
            self.clients["project1-member"], params="--node {0}".format(self.node)
        )

        self.assertEqual(
            node_network_list[0]["Network"],
            "{0} ({1})".format(network["name"], network["provider:segmentation_id"]),
        )

        utils.esi_node_network_detach(
            self.clients["project1-member"], self.node, port["name"]
        )
        node_network_list = utils.esi_node_network_list(
            self.clients["project1-member"], params="--node {0}".format(self.node)
        )
        self.assertEqual(node_network_list[0]["Network"], None)

    def test_owner_attach_and_detach(self):
        """Tests that owner can attach/detach a network from a node

        Test steps:
        1) Admin sets owner of node to User 1.
        2) User 1 retrieves information about the node.
        3) User 1 sets provision state of the node to manageable.
        4) User 1 creates a network.
        5) User 1 creates a port on the network.
        6) User 1 attaches node to network using port.
        7) User 1 detaches node from network
        8) (cleanup) Delete the port created in step 5.
        9) (cleanup) Delete the network created in step 4.
        10) (cleanup) Undeploy the node
        11) (cleanup) Reset the owner of the node.

        """

        node = utils.node_show(self.clients["admin"], self.node)
        utils.node_set(
            self.clients["admin"], self.node, "owner", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "owner", node["owner"]
        )

        node = utils.node_show(self.clients["project1-member"], self.node)
        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(
                self.clients["project1-member"], self.node, "manage"
            )

        network = utils.network_create(self.clients["project1-member"])
        self.addCleanup(utils.network_delete, self.clients["admin"], network["name"])
        port = utils.port_create(self.clients["project1-member"], network["name"])
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        utils.esi_node_network_attach(
            self.clients["project1-member"], self.node, port["name"]
        )

        node_network_list = utils.esi_node_network_list(
            self.clients["project1-member"], params="--node {0}".format(self.node)
        )

        self.assertEqual(
            node_network_list[0]["Network"],
            "{0} ({1})".format(network["name"], network["provider:segmentation_id"]),
        )

        utils.esi_node_network_detach(
            self.clients["project1-member"], self.node, port["name"]
        )
        node_network_list = utils.esi_node_network_list(
            self.clients["project1-member"], params="--node {0}".format(self.node)
        )
        self.assertEqual(node_network_list[0]["Network"], None)

    def test_nonadmin_no_node_cannot_attach_or_detach(self):
        """Tests nonadmin no node permission node/network operations

        Tests that a nonadmin who is neither an owner nor an lessee
        cannot attach or detach a network from a node

        Test steps:
        1) User 1 creates a network.
        2) User 1 creates a port on the network.
        3) User 1 fails to attach node to network using port.
        4) Admin attaches node to network using port.
        5) User 1 fails to detach node from network
        6) (cleanup) Detach port from node.
        7) (cleanup) Delete the port created in step 2.
        8) (cleanup) Delete the network created in step 1.
        9) (cleanup) Undeploy the node

        """

        node = utils.node_show(self.clients["admin"], self.node)

        network = utils.network_create(self.clients["project1-member"])
        self.addCleanup(utils.network_delete, self.clients["admin"], network["name"])
        port = utils.port_create(self.clients["project1-member"], network["name"])
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        self.assertRaises(
            exceptions.CommandFailed,
            utils.esi_node_network_attach,
            self.clients["project1-member"],
            self.node,
            port["name"],
        )

        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(self.clients["admin"], self.node, "manage")

        utils.esi_node_network_attach(self.clients["admin"], self.node, port["name"])
        self.addCleanup(
            utils.esi_node_network_detach,
            self.clients["admin"],
            self.node,
            port["name"],
        )

        self.assertRaises(
            exceptions.CommandFailed,
            utils.esi_node_network_detach,
            self.clients["project1-member"],
            self.node,
            port["name"],
        )

    def test_nonadmin_no_network_cannot_attach(self):
        """Tests nonadmin no-permission network node operation

        Tests that a nonadmin who is an owner/lessee cannot
        attach a private network that they do not have permission
        to use from a node

        Test steps:
        1) Admin sets lessee of node to User 1.
        2) User 1 retrieves information about the node.
        3) User 1 sets provision state of the node to manageable.
        4) User 1 creates a network.
        5) User 1 creates a port on the network.
        6) User 1 attaches node to network using port.
        7) User 1 detaches node from network
        8) (cleanup) Delete the port created in step 5.
        9) (cleanup) Delete the network created in step 4.
        10) (cleanup) Undeploy the node
        11) (cleanup) Reset the lessee of the node.

        """

        node = utils.node_show(self.clients["admin"], self.node)
        utils.node_set(
            self.clients["admin"], self.node, "lessee", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "lessee", node["lessee"]
        )

        network = utils.network_create(self.clients["admin"])
        self.addCleanup(utils.network_delete, self.clients["admin"], network["name"])
        port = utils.port_create(self.clients["admin"], network["name"])
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        node = utils.node_show(self.clients["project1-member"], self.node)
        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(
                self.clients["project1-member"], self.node, "manage"
            )

        self.assertRaises(
            exceptions.CommandFailed,
            utils.esi_node_network_attach,
            self.clients["project1-member"],
            self.node,
            port["name"],
        )

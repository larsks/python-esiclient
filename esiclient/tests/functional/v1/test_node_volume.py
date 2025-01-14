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
class NodeVolumeAttachTests(base.ESIBaseTestClass):
    """Functional tests for esi node volume attach commands."""

    @classmethod
    def setUpClass(cls):
        super(NodeVolumeAttachTests, cls).setUpClass()

        cls._init_dummy_project(cls, "project1", "member")
        cls._init_dummy_project(cls, "project2", "member")

    def setUp(self):
        super(NodeVolumeAttachTests, self).setUp()
        self.clients = NodeVolumeAttachTests.clients
        self.users = NodeVolumeAttachTests.users
        self.projects = NodeVolumeAttachTests.projects
        self.config = NodeVolumeAttachTests.config

        if "test_node_ident" not in self.config["functional"]:
            self.fail("test_node_ident must be specified in test config")
        if "storage_network_ident" not in self.config["functional"]:
            self.fail("storage_network_ident must be specified in test config")
        if "test_volume_ident" not in self.config["functional"]:
            self.fail("test_volume_ident must be specified in test config")

        self.node = self.config["functional"]["test_node_ident"]
        self.storage_network = self.config["functional"]["storage_network_ident"]
        self.volume = self.config["functional"]["test_volume_ident"]

    def test_owner_can_attach_volume(self):
        """Tests node owner can attach volume.

        Tests that an owner with no access to the volume
            cannot run `esi node volume attach`
            Test steps:
            1) Set project1 to the owner of the node
            2) Transfer volume to project
            3) Project1 creates a port on storage network
            4) Project1 Set node state to 'available'
            5) Project1 runs
               `esi node volume attach --port <port> <node> <volume>`
            6) (cleanup) Undeploy the node
            7) (cleanup) Delete the port created in step 3
            8) (cleanup) Transfer volume back to admin
            9) (cleanup) Reset node owner

        """

        node = utils.node_show(self.clients["admin"], self.node)
        utils.node_set(
            self.clients["admin"], self.node, "owner", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "owner", node["owner"]
        )
        utils.volume_transfer_request_create_and_accept(
            self.clients["admin"], self.clients["project1-member"], self.volume
        )
        self.addCleanup(
            utils.volume_transfer_request_create_and_accept,
            self.clients["project1-member"],
            self.clients["admin"],
            self.volume,
        )

        port = utils.port_create(self.clients["project1-member"], self.storage_network)
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        node = utils.node_show(self.clients["project1-member"], self.node)
        if node["provision_state"] != "available":
            utils.node_set_provision_state(
                self.clients["project1-member"], node["name"], "provide"
            )

        utils.esi_node_volume_attach(
            self.clients["project1-member"], port["name"], node["name"], self.volume
        )
        self.addCleanup(
            utils.node_set_provision_state,
            self.clients["admin"],
            node["name"],
            "undeploy",
        )

    def test_lessee_can_attach_volume(self):
        """Tests node lessee can attach volume.

        Tests that an lessee with no access to the volume
            cannot run `esi node volume attach`
            Test steps:
            1) Set project1 to the lessee of the node
            2) Transfer volume to project
            3) Project1 creates a port on storage network
            4) Project1 Set node state to 'available'
            5) Project1 runs
               `esi node volume attach --port <port> <node> <volume>`
            6) (cleanup) Undeploy the node
            7) (cleanup) Delete the port created in step 3
            8) (cleanup) Transfer volume back to admin
            9) (cleanup) Reset node lessee

        """

        node = utils.node_show(self.clients["admin"], self.node)
        utils.node_set(
            self.clients["admin"], self.node, "lessee", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "lessee", node["lessee"]
        )
        utils.volume_transfer_request_create_and_accept(
            self.clients["admin"], self.clients["project1-member"], self.volume
        )
        self.addCleanup(
            utils.volume_transfer_request_create_and_accept,
            self.clients["project1-member"],
            self.clients["admin"],
            self.volume,
        )

        port = utils.port_create(self.clients["project1-member"], self.storage_network)
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        node = utils.node_show(self.clients["project1-member"], self.node)
        if node["provision_state"] != "available":
            utils.node_set_provision_state(
                self.clients["project1-member"], node["name"], "provide"
            )

        utils.esi_node_volume_attach(
            self.clients["project1-member"], port["name"], node["name"], self.volume
        )
        self.addCleanup(
            utils.node_set_provision_state,
            self.clients["admin"],
            node["name"],
            "undeploy",
        )

    def test_non_owner_lessee_cannot_attach_volume(self):
        """Tests non owner and non lessee node volume attach functionality.

        Tests that a project which is not set to a node's 'owner' nor
            'lessee' cannot run `esi node volume attach`
            Test steps:
            1) Set node state to 'available'
            2) Transfer volume to project
            4) Project1 creates a port on storage network
            4) Check that the project cannot run
               `esi node volume attach --port <port> <node> <volume>`
            5) (cleanup) Delete the port created in step 4
            6) (cleanup) Transfer volume back to admin

        """

        node = utils.node_show(self.clients["admin"], self.node)
        if node["provision_state"] != "available":
            utils.node_set_provision_state(
                self.clients["admin"], node["name"], "provide"
            )
        utils.volume_transfer_request_create_and_accept(
            self.clients["admin"], self.clients["project1-member"], self.volume
        )
        self.addCleanup(
            utils.volume_transfer_request_create_and_accept,
            self.clients["project1-member"],
            self.clients["admin"],
            self.volume,
        )
        port = utils.port_create(self.clients["project1-member"], self.storage_network)
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        self.assertRaises(
            exceptions.CommandFailed,
            utils.esi_node_volume_attach,
            self.clients["project1-member"],
            port["name"],
            node["name"],
            self.volume,
        )

    def test_owner_volume_no_access_cannot_attach_volume(self):
        """Tests no volume access node volume attach functionality.

        Tests that an owner with no access to the volume
            cannot run `esi node volume attach`
            Test steps:
            1) Set node state to 'available'
            2) Set project1 to the owner of the node
            3) Project2 creates a private volume
            4) Project1 creates a port on storage network
            5) Check that project1 cannot run
               `esi node volume attach --port <port> <node> <volume>`
            6) (cleanup) Delete the port created in step 4
            7) (cleanup) Delete the volume created in step 3
            8) (cleanup) Reset node owner

        """

        node = utils.node_show(self.clients["admin"], self.node)
        utils.node_set(
            self.clients["admin"], self.node, "owner", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "owner", node["owner"]
        )

        node = utils.node_show(self.clients["project1-member"], self.node)
        if node["provision_state"] != "available":
            utils.node_set_provision_state(
                self.clients["project1-member"], node["name"], "provide"
            )
        volume = utils.volume_create(self.clients["project2-member"])
        self.addCleanup(utils.volume_delete, self.clients["admin"], volume["id"])
        port = utils.port_create(self.clients["project1-member"], self.storage_network)
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        self.assertRaises(
            exceptions.CommandFailed,
            utils.esi_node_volume_attach,
            self.clients["project1-member"],
            port["name"],
            node["name"],
            volume["name"],
        )

    def test_lessee_volume_no_access_cannot_attach_volume(self):
        """Tests no volume access node volume attach functionality.

        Tests that an lessee with no access to the volume
            cannot run `esi node volume attach`
            Test steps:
            1) Set node state to 'available'
            2) Set project1 to the lessee of the node
            3) Project2 creates a private volume
            4) Project1 creates a port on storage network
            5) Check that project1 cannot run
               `esi node volume attach --port <port> <node> <volume>`
            6) (cleanup) Delete the port created in step 4
            7) (cleanup) Delete the volume created in step 3
            8) (cleanup) Reset node lessee

        """

        node = utils.node_show(self.clients["admin"], self.node)
        utils.node_set(
            self.clients["admin"], self.node, "lessee", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "lessee", node["lessee"]
        )

        node = utils.node_show(self.clients["project1-member"], self.node)
        if node["provision_state"] != "available":
            utils.node_set_provision_state(
                self.clients["project1-member"], node["name"], "provide"
            )
        volume = utils.volume_create(self.clients["project2-member"])
        self.addCleanup(utils.volume_delete, self.clients["admin"], volume["id"])
        port = utils.port_create(self.clients["project1-member"], self.storage_network)
        self.addCleanup(utils.port_delete, self.clients["admin"], port["name"])

        self.assertRaises(
            exceptions.CommandFailed,
            utils.esi_node_volume_attach,
            self.clients["project1-member"],
            port["name"],
            node["name"],
            volume["name"],
        )

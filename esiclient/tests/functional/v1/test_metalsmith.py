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
class MetalsmithDeployTests(base.ESIBaseTestClass):
    """Functional tests for metalsmith node deploy commands."""

    @classmethod
    def setUpClass(cls):
        super(MetalsmithDeployTests, cls).setUpClass()

        cls._init_dummy_project(cls, "project1", "member")

    def setUp(self):
        super(MetalsmithDeployTests, self).setUp()
        self.clients = MetalsmithDeployTests.clients
        self.metalsmith_clients = MetalsmithDeployTests.metalsmith_clients
        self.users = MetalsmithDeployTests.users
        self.projects = MetalsmithDeployTests.projects
        self.config = MetalsmithDeployTests.config

        if "test_node_ident" not in self.config["functional"]:
            self.fail("test_node_ident must be specified in test config")
        if "provisioning_network_ident" not in self.config["functional"]:
            self.fail("provisioning_network_ident must be specified in test config")
        if "provisioning_image_ident" not in self.config["functional"]:
            self.fail("provisioning_image_ident must be specified in test config")

        self.node = self.config["functional"]["test_node_ident"]
        self.provisioning_network_ident = self.config["functional"][
            "provisioning_network_ident"
        ]
        self.provisioning_image_ident = self.config["functional"][
            "provisioning_image_ident"
        ]

    def test_owner_deploy_node_metalsmith(self):
        """Tests owner metalsmith node deploy functionality.

        Tests that a project which is set to a node's 'owner'
            can run `metalsmith deploy <image> <node>`
            Test steps:
            1) Admin sets owner of node to project1
            2) Project1 checks that the node state is 'available'
            3) Project1 successfully runs
               `metalsmith deploy <image> <node>`
            4) (cleanup) Undeploy the node
            5) (cleanup) Reset the node owner

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

        utils.metalsmith_deploy(
            self.metalsmith_clients["project1-member"],
            self.provisioning_image_ident,
            self.provisioning_network_ident,
        )
        self.addCleanup(
            utils.node_set_provision_state,
            self.clients["admin"],
            node["name"],
            "undeploy",
        )

    def test_lessee_deploy_node_metalsmith(self):
        """Tests lessee metalsmith node deploy functionality.

        Tests that a project which is set to a node's 'lessee'
            can run `metalsmith deploy <image> <node>`
            Test steps:
            1) Admin sets lessee of node to project1
            2) Project1 checks that the node state is 'available'
            3) Project1 successfully runs
               `metalsmith deploy <image> <node>`
            4) (cleanup) Undeploy the node
            5) (cleanup) Reset the node lessee

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

        utils.metalsmith_deploy(
            self.metalsmith_clients["project1-member"],
            self.provisioning_image_ident,
            self.provisioning_network_ident,
        )
        self.addCleanup(
            utils.node_set_provision_state,
            self.clients["admin"],
            node["name"],
            "undeploy",
        )

    def test_non_owner_lessee_cannot_deploy_node_metalsmith(self):
        """Tests non owner/lessee metalsmith node deploy functionality.

        Tests that a project which is not set to a node's 'owner' nor
            'lessee' cannot run `metalsmith deploy <image> <node>`
            Test steps:
            1) Check that the node state is 'available'
            2) Check that the project cannot run
               `metalsmith deploy <image> <node>`

        """
        node = utils.node_show(self.clients["admin"], self.node)
        if node["provision_state"] != "available":
            utils.node_set_provision_state(
                self.clients["admin"], node["name"], "provide"
            )

        self.assertRaises(
            exceptions.CommandFailed,
            utils.metalsmith_deploy,
            self.metalsmith_clients["project1-member"],
            self.provisioning_image_ident,
            self.provisioning_network_ident,
        )

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

import time

import ddt
from tempest.lib import exceptions

from esiclient.tests.functional import base
from esiclient.tests.functional import utils


@ddt.ddt
class NodePowerTests(base.ESIBaseTestClass):
    """Functional tests for esi node power commands."""

    @classmethod
    def setUpClass(cls):
        super(NodePowerTests, cls).setUpClass()

        cls._init_dummy_project(cls, "random", "member")

    def setUp(self):
        super(NodePowerTests, self).setUp()
        self.clients = NodePowerTests.clients
        self.users = NodePowerTests.users
        self.projects = NodePowerTests.projects

    def test_owner_can_node_power_on_off(self):
        """Tests owner power functionality.

        Tests owner `baremetal node power on <node>` and
        `baremetal node power off <node>`.

        Test steps:
        1) Create a node and set its 'owner' field to project_id of a
            a random project.
        2) Check that the project can run `node power on` and
            `node power off`
        3) (cleanup) Delete the node created in step 1.

        """
        node = utils.node_create(self.clients["admin"])
        self.addCleanup(utils.node_delete, self.clients["admin"], node["name"])

        utils.node_set(
            self.clients["admin"], node["name"], "owner", self.projects["random"]["id"]
        )

        utils.node_power_on(self.clients["random-member"], node["name"])
        utils.node_power_off(self.clients["random-member"], node["name"])

    def test_lessee_can_node_power_on_off(self):
        """Tests lessee power funcitonality.

        Tests that a node's 'lessee' can `baremetal node power on <node>`
        and `baremetal node power off <node>.

        Test steps:
            1) Create a node and set its 'lessee' field to project_id of a
                a random project.
            2) Check that the project can run `node power on` and
                `node power off`
            3) (cleanup) Delete the node created in step 1.
        """
        node = utils.node_create(self.clients["admin"])
        self.addCleanup(utils.node_delete, self.clients["admin"], node["name"])

        utils.node_set(
            self.clients["admin"], node["name"], "lessee", self.projects["random"]["id"]
        )

        utils.node_power_on(self.clients["random-member"], node["name"])
        utils.node_power_off(self.clients["random-member"], node["name"])

    def test_non_owner_lessee_cannot_node_power_on_off(self):
        """Tests non owner and non lessee power functionality.

        Tests that a project which is not set to a node's 'owner' nor
            'lessee' cannot run `baremetal node power on <node>` or
            `baremetal node power off <node>.
            Test steps:
            1) Create a node
            2) Check that the project cannot run `node power on` or
                `node power off`
            3) (cleanup) Delete the node created in step 1.
        """
        node = utils.node_create(self.clients["admin"])
        self.addCleanup(utils.node_delete, self.clients["admin"], node["name"])

        self.assertRaises(
            exceptions.CommandFailed,
            utils.node_power_on,
            self.clients["random-member"],
            node["name"],
        )

        self.assertRaises(
            exceptions.CommandFailed,
            utils.node_power_off,
            self.clients["random-member"],
            node["name"],
        )

    def test_admin_can_node_power_on_off(self):
        """Tests admin power functionality.

        Tests that an admin project which is not set to a node's 'owner'
            nor 'lessee' can run `baremetal node power on <node>` and
            `baremetal node power off <node>.
            Test steps:
            1) Create a node
            2) Check that the project can run `node power on` and
                `node power off`
            3) (cleanup) Delete the node created in step 1.
        """
        node = utils.node_create(self.clients["admin"], name="owned")
        self.addCleanup(utils.node_delete, self.clients["admin"], node["name"])

        utils.node_power_on(self.clients["admin"], node["name"])
        utils.node_power_off(self.clients["admin"], node["name"])


@ddt.ddt
class NodeConsoleTests(base.ESIBaseTestClass):
    """Functional tests for esi node console commands."""

    @classmethod
    def setUpClass(cls):
        super(NodeConsoleTests, cls).setUpClass()

        cls._init_dummy_project(cls, "random", "member")

    def setUp(self):
        super(NodeConsoleTests, self).setUp()
        self.clients = NodeConsoleTests.clients
        self.users = NodeConsoleTests.users
        self.projects = NodeConsoleTests.projects

        if "test_node_ident" not in self.config["functional"]:
            self.fail("test_node_ident must be specified in test config")
        self.node = self.config["functional"]["test_node_ident"]

    def test_admin_can_enable_console(self):
        """Tests admin console functionality.

        Tests that an admin project which is not set to a node's 'owner'
        nor 'lessee' can perform the steps to setup an ipmitool-socat
        serial console.

        Test steps:
            1) Check that the project can run command
                `baremetal node console enable <node>`
            2) Check that project can run command
                baremetal node console show <node>`
            3) Check that project can run command
                `baremetal node console disable <node>`
            4) (cleanup) disable console
        """

        node = utils.node_show(self.clients["admin"], self.node)
        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(self.clients["admin"], self.node, "manage")

        utils.node_console_enable(self.clients["admin"], self.node)
        self.addCleanup(
            utils.node_console_disable, self.clients["admin"], self.node, fail_ok=True
        )
        time.sleep(10)
        console = utils.node_console_show(self.clients["admin"], self.node)
        assert console["console_enabled"]

        utils.node_console_disable(self.clients["admin"], self.node)
        time.sleep(10)
        console = utils.node_console_show(self.clients["admin"], self.node)
        assert not console["console_enabled"]

    def test_owner_can_enable_console(self):
        """Tests owner console functionality.

        Tests that an owner can perform the steps to setup an ipmitool-socat
        serial console.

        Test steps:
            1) Set owner of node to random project
            2) Check that the owner can run command
                `baremetal node console enable <node>`
            3) Check that owner can run command
                baremetal node console show <node>`
            4) Check that owner can run command
                `baremetal node console disable <node>`
            5) (cleanup) Set the owner back to what it was before test
            6) (cleanup) disable console
        """

        node = utils.node_show(self.clients["admin"], self.node)
        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(self.clients["admin"], self.node, "manage")

        utils.node_set(
            self.clients["admin"], self.node, "owner", self.projects["random"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "owner", node["owner"]
        )

        utils.node_console_enable(self.clients["random-member"], self.node)
        self.addCleanup(
            utils.node_console_disable, self.clients["admin"], self.node, fail_ok=True
        )
        time.sleep(10)
        console = utils.node_console_show(self.clients["random-member"], self.node)
        assert console["console_enabled"]

        utils.node_console_disable(self.clients["random-member"], self.node)
        time.sleep(10)
        console = utils.node_console_show(self.clients["random-member"], self.node)
        assert not console["console_enabled"]

    def test_lessee_can_enable_console(self):
        """Tests lessee console functionality.

        Tests that a lessee can perform the steps to setup an ipmitool-socat
        serial console.

        Test steps:
            1) Set lessee of node to random project
            2) Check that the lessee can run command
                `baremetal node console enable <node>`
            3) Check that lessee can run command
                baremetal node console show <node>`
            4) Check that lessee can run command
                `baremetal node console disable <node>`
            5) (cleanup) Set the lessee back to what it was before test
            6) (cleanup) disable console
        """

        node = utils.node_show(self.clients["admin"], self.node)
        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(self.clients["admin"], self.node, "manage")

        utils.node_set(
            self.clients["admin"], self.node, "lessee", self.projects["random"]["id"]
        )
        self.addCleanup(
            utils.node_set, self.clients["admin"], self.node, "lessee", node["lessee"]
        )

        utils.node_console_enable(self.clients["random-member"], self.node)
        self.addCleanup(
            utils.node_console_disable, self.clients["admin"], self.node, fail_ok=True
        )
        time.sleep(10)
        console = utils.node_console_show(self.clients["random-member"], self.node)
        assert console["console_enabled"]

        utils.node_console_disable(self.clients["random-member"], self.node)
        time.sleep(10)
        console = utils.node_console_show(self.clients["random-member"], self.node)
        assert not console["console_enabled"]

    def test_random_cannot_enable_console(self):
        """Tests random project console functionality.

        Tests that a random project cannot perform the steps to setup an
        ipmitool-socat serial console.

        Test steps:
            1) Check that the project cannot run command
                `baremetal node console enable <node>`
            2) Check that project cannot run command
                baremetal node console show <node>`
            3) Check that project cannot run command
                `baremetal node console disable <node>`
        """

        node = utils.node_show(self.clients["admin"], self.node)
        if node["provision_state"] != "manageable":
            utils.node_set_provision_state(self.clients["admin"], self.node, "manage")

        self.assertRaises(
            exceptions.CommandFailed,
            utils.node_console_enable,
            self.clients["random-member"],
            self.node,
        )

        self.assertRaises(
            exceptions.CommandFailed,
            utils.node_console_disable,
            self.clients["random-member"],
            self.node,
        )

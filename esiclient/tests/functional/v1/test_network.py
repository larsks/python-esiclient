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
class NetworkTests(base.ESIBaseTestClass):
    """Functional tests for ESI network commands."""

    @classmethod
    def setUpClass(cls):
        super(NetworkTests, cls).setUpClass()
        cls._init_dummy_project(cls, "project1", "member")
        cls._init_dummy_project(cls, "project2", "member")

    def setUp(self):
        super(NetworkTests, self).setUp()
        self.clients = NetworkTests.clients
        self.users = NetworkTests.users
        self.projects = NetworkTests.projects

    def test_admin_public_network(self):
        """Tests that an admin can create a public network that nonadmins can view.

        Test steps:
        1) Admin creates public network.
        2) Nonadmin retrieves information about the network.
        3) (cleanup) Delete the network created in step 1.

        """

        network = utils.network_create(self.clients["admin"], shared="share")
        self.addCleanup(utils.network_delete, self.clients["admin"], network["name"])

        network_show = utils.network_show(
            self.clients["project1-member"], network["name"]
        )
        self.assertEqual(network["id"], network_show["id"])

    def test_non_admin_private_network(self):
        """Tests that a nonadmin can create a private network.

        Test steps:
        1) User 1 creates network.
        2) User 1 retrieves information about the network.
        3) User 2 cannot retrieve information about the network.
        4) User 1 shares network with User 2
        5) User 2 can retrieve information about the network.
        6) User 1 unshares network with User 2
        7) User 2 can no longer retrieve information about the network.
        8) (cleanup) Delete the network created in step 1.

        """

        network = utils.network_create(self.clients["project1-member"])
        self.addCleanup(
            utils.network_delete, self.clients["project1-member"], network["name"]
        )

        network_show = utils.network_show(
            self.clients["project1-member"], network["name"]
        )
        self.assertEqual(network["id"], network_show["id"])
        self.assertRaises(
            exceptions.CommandFailed,
            utils.network_show,
            self.clients["project2-member"],
            network["name"],
        )

        network_rbac = utils.network_rbac_create(
            self.clients["project1-member"],
            self.projects["project2"]["id"],
            network["name"],
        )
        network_show_2 = utils.network_show(
            self.clients["project2-member"], network["name"]
        )
        self.assertEqual(network["id"], network_show_2["id"])

        utils.network_rbac_delete(self.clients["project1-member"], network_rbac["id"])
        self.assertRaises(
            exceptions.CommandFailed,
            utils.network_show,
            self.clients["project2-member"],
            network["name"],
        )

    def test_non_admin_quota(self):
        """Tests that nonadmin network creation is limited by quota.

        Test steps:
        1) Admin set project network quota to 1.
        2) User successfully creates network.
        3) User fails to create second network.
        4) (cleanup) Reset the user network quota.
        5) (cleanup) Delete the network created in step 2.

        """

        quota = utils.quota_show(self.clients["admin"], self.projects["project1"]["id"])
        utils.quota_set(
            self.clients["admin"], "--networks 1", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.quota_set,
            self.clients["admin"],
            "--networks {0}".format(quota["networks"]),
            self.projects["project1"]["id"],
        )

        network1 = utils.network_create(self.clients["project1-member"])
        self.addCleanup(
            utils.network_delete, self.clients["project1-member"], network1["name"]
        )
        self.assertRaises(
            exceptions.CommandFailed,
            utils.network_create,
            self.clients["project1-member"],
        )

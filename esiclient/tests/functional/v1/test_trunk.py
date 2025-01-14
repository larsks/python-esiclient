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

from esiclient.tests.functional import base
from esiclient.tests.functional import utils


@ddt.ddt
class TrunkTests(base.ESIBaseTestClass):
    """Functional tests for ESI network commands."""

    @classmethod
    def setUpClass(cls):
        super(TrunkTests, cls).setUpClass()
        cls._init_dummy_project(cls, "project1", "member")
        cls._init_dummy_project(cls, "project2", "member")

    def setUp(self):
        super(TrunkTests, self).setUp()
        self.clients = TrunkTests.clients
        self.users = TrunkTests.users
        self.projects = TrunkTests.projects

    def test_non_admin_trunk_port(self):
        """Tests that a nonadmin can create and update a trunk port

        Test steps:
        1) User 1 lists trunks.
        2) User 2 lists trunks.
        3) User 1 creates a network.
        4) User 1 creates a trunk using native network from step 3.
        5) User 1 lists trunks and sees trunk from step 4.
        6) User 2 lists trunks and does not see trunk.
        7) User 1 creates a second network.
        8) User 1 adds network from step 7 to trunk as tagged network.
        9) User 1 lists trunks and sees updated trunk.
        10) User 1 removes network from step 7 from trunk.
        11) User 1 lists trunks and sees updated trunk.
        12) User 1 deletes trunk.
        13) (cleanup) Delete the network created in step 3.
        14) (cleanup) Delete the trunk created in step 4.
        15) (cleanup) Delete the network created in step 7.

        """

        trunks = utils.esi_trunk_list(self.clients["project1-member"])
        self.assertEqual(len(trunks), 0)
        trunks = utils.esi_trunk_list(self.clients["project2-member"])
        self.assertEqual(len(trunks), 0)

        network1 = utils.network_create(self.clients["project1-member"])
        self.addCleanup(utils.network_delete, self.clients["admin"], network1["name"])

        trunk = utils.esi_trunk_create(
            self.clients["project1-member"], network1["name"]
        )
        self.addCleanup(
            utils.esi_trunk_delete, self.clients["admin"], trunk["Trunk"], fail_ok=True
        )

        trunks = utils.esi_trunk_list(self.clients["project1-member"])
        self.assertEqual(len(trunks), 1)
        self.assertEqual(
            trunks[0]["Network"],
            "{0} ({1})".format(network1["name"], network1["provider:segmentation_id"]),
        )
        trunks = utils.esi_trunk_list(self.clients["project2-member"])
        self.assertEqual(len(trunks), 0)

        network2 = utils.network_create(self.clients["project1-member"])
        self.addCleanup(utils.network_delete, self.clients["admin"], network2["name"])

        utils.esi_trunk_add_network(
            self.clients["project1-member"], trunk["Trunk"], network2["name"]
        )
        trunks = utils.esi_trunk_list(self.clients["project1-member"])
        self.assertEqual(
            trunks[0]["Network"],
            "{0} ({1})\n{2} ({3})".format(
                network1["name"],
                network1["provider:segmentation_id"],
                network2["name"],
                network2["provider:segmentation_id"],
            ),
        )

        utils.esi_trunk_remove_network(
            self.clients["project1-member"], trunk["Trunk"], network2["name"]
        )
        trunks = utils.esi_trunk_list(self.clients["project1-member"])
        self.assertEqual(
            trunks[0]["Network"],
            "{0} ({1})".format(network1["name"], network1["provider:segmentation_id"]),
        )

        utils.esi_trunk_delete(self.clients["project1-member"], trunk["Trunk"])

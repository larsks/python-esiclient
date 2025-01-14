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
class VolumeTests(base.ESIBaseTestClass):
    """Functional tests for ESI network commands."""

    @classmethod
    def setUpClass(cls):
        super(VolumeTests, cls).setUpClass()
        cls._init_dummy_project(cls, "project1", "member")
        cls._init_dummy_project(cls, "project2", "member")

    def setUp(self):
        super(VolumeTests, self).setUp()
        self.clients = VolumeTests.clients
        self.users = VolumeTests.users
        self.projects = VolumeTests.projects

    def test_non_admin_volume(self):
        """Tests that nonadmin can create and delete volume

        Test steps:
        1) User creates volume
        2) User deletes volume
        3) (cleanup) Delete the volume created in step 1.

        """

        volume = utils.volume_create(self.clients["project1-member"])
        self.addCleanup(
            utils.volume_delete, self.clients["admin"], volume["id"], fail_ok=True
        )
        utils.volume_delete(self.clients["project1-member"], volume["id"])

    def test_non_admin_volume_quota(self):
        """Tests that nonadmin volume creation is limited by quota.

        Test steps:
        1) Admin set project volume quota to 1.
        2) User successfully creates volume.
        3) User fails to create second volume.
        4) (cleanup) Reset the user volume quota.
        5) (cleanup) Delete the volume created in step 2.

        """

        quota = utils.quota_show(self.clients["admin"], self.projects["project1"]["id"])
        utils.quota_set(
            self.clients["admin"], "--volumes 1", self.projects["project1"]["id"]
        )
        self.addCleanup(
            utils.quota_set,
            self.clients["admin"],
            "--volumes {0}".format(quota["volumes"]),
            self.projects["project1"]["id"],
        )

        volume = utils.volume_create(self.clients["project1-member"])
        self.addCleanup(utils.volume_delete, self.clients["admin"], volume["id"])
        self.assertRaises(
            exceptions.CommandFailed,
            utils.volume_create,
            self.clients["project1-member"],
        )

    def test_non_admin_volume_share(self):
        """Tests that nonadmin can share volume

        Test steps:
        1) User creates volume
        2) User deletes volume
        3) (cleanup) Delete the volume created in step 1.

        """

        volume = utils.volume_create(self.clients["project1-member"])
        self.addCleanup(utils.volume_delete, self.clients["admin"], volume["id"])

        utils.volume_show(self.clients["project1-member"], volume["id"])
        self.assertRaises(
            exceptions.CommandFailed,
            utils.volume_show,
            self.clients["project2-member"],
            volume["id"],
        )

        transfer_request = utils.volume_transfer_request_create(
            self.clients["project1-member"], volume["id"]
        )
        utils.volume_transfer_request_accept(
            self.clients["project2-member"],
            transfer_request["id"],
            transfer_request["auth_key"],
        )

        self.assertRaises(
            exceptions.CommandFailed,
            utils.volume_show,
            self.clients["project1-member"],
            volume["id"],
        )
        utils.volume_show(self.clients["project2-member"], volume["id"])

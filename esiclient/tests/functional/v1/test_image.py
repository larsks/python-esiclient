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
class ImageTests(base.ESIBaseTestClass):
    """Functional tests for ESI network commands."""

    @classmethod
    def setUpClass(cls):
        super(ImageTests, cls).setUpClass()
        cls._init_dummy_project(cls, "project1", "member")
        cls._init_dummy_project(cls, "project2", "member")

    def setUp(self):
        super(ImageTests, self).setUp()
        self.clients = ImageTests.clients
        self.users = ImageTests.users
        self.projects = ImageTests.projects
        if "image_path" not in ImageTests.config["functional"]:
            self.fail("image_path must be specified in test config")
        self.image_path = ImageTests.config["functional"]["image_path"]

    def test_admin_image_public_and_private(self):
        """Tests that an admin can create a public image and set it to private

        Test steps:
        1) Admin creates public image.
        2) User 1 can view image.
        3) Admin sets image to private.
        4) User 1 can no longer view image.
        5) Admin deletes image.
        6) (cleanup) Delete the image created in step 1.

        """

        image = utils.image_create(self.clients["admin"], self.image_path)
        self.addCleanup(
            utils.image_delete, self.clients["admin"], image["name"], fail_ok=True
        )

        image_show = utils.image_show(self.clients["project1-member"], image["name"])
        self.assertEqual(image["id"], image_show["id"])

        utils.image_set(self.clients["admin"], image["name"], "--private")
        self.assertRaises(
            exceptions.CommandFailed,
            utils.image_show,
            self.clients["project1-member"],
            image["name"],
        )

        utils.image_delete(self.clients["admin"], image["name"])

    def test_nonadmin_image_public_exception(self):
        """Tests that a non-admin cannot create a public image

        Test steps:
        1) User 1 fails to create a public image.

        """

        self.assertRaises(
            exceptions.CommandFailed,
            utils.image_create,
            self.clients["project1-member"],
            self.image_path,
        )

    def test_nonadmin_image_private(self):
        """Tests that a non-admin can create a private image

        Test steps:
        1) User 1 creates private image.
        2) User 2 fails to view image.
        3) User 1 deletes image.
        4) (cleanup) Delete the image created in step 1.

        """

        image = utils.image_create(
            self.clients["project1-member"], self.image_path, visibility="private"
        )
        self.addCleanup(
            utils.image_delete, self.clients["admin"], image["name"], fail_ok=True
        )

        self.assertRaises(
            exceptions.CommandFailed,
            utils.image_show,
            self.clients["project2-member"],
            image["id"],
        )

        utils.image_delete(self.clients["project1-member"], image["name"])

    def test_nonadmin_image_shared(self):
        """Tests that a non-admin can share a private image

        Test steps:
        1) User 1 creates private image.
        2) User 2 fails to view image.
        3) User 1 sets image visibility to shared.
        4) User 1 shares image with user 2.
        5) User 2 can view image.
        6) User 1 modifies image.
        7) User 2 fails to modify image.
        8) User 1 unshares image with user 2.
        9) User 2 fails to view image.
        10) User 1 deletes image.
        11) (cleanup) Delete the image created in step 1.

        """

        image = utils.image_create(
            self.clients["project1-member"], self.image_path, visibility="private"
        )
        self.addCleanup(
            utils.image_delete, self.clients["admin"], image["name"], fail_ok=True
        )

        utils.image_set(self.clients["project1-member"], image["id"], "--shared")
        utils.image_add_project(
            self.clients["project1-member"],
            image["id"],
            self.projects["project2"]["id"],
        )

        image_show = utils.image_show(self.clients["project2-member"], image["id"])
        self.assertEqual(image_show["name"], image["name"])

        new_image_name = "{0}_change".format(image["name"])
        utils.image_set(
            self.clients["project1-member"],
            image["id"],
            "--name {0}".format(new_image_name),
        )
        image = utils.image_show(self.clients["project1-member"], image["id"])
        self.assertEqual(image["name"], new_image_name)

        fail_image_name = "{0}_fail".format(image["name"])
        self.assertRaises(
            exceptions.CommandFailed,
            utils.image_set,
            self.clients["project2-member"],
            image["id"],
            "--name {0}".format(fail_image_name),
        )

        utils.image_remove_project(
            self.clients["project1-member"],
            image["id"],
            self.projects["project2"]["id"],
        )
        self.assertRaises(
            exceptions.CommandFailed,
            utils.image_show,
            self.clients["project2-member"],
            image["id"],
        )

        utils.image_delete(self.clients["project1-member"], image["name"])

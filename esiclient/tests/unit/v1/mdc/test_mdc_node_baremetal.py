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

from unittest import mock
import munch

from esiclient.tests.unit import base
from esiclient.v1.mdc import mdc_node_baremetal


class TestMDCBaremetalNodeList(base.TestCommand):
    def setUp(self):
        super(TestMDCBaremetalNodeList, self).setUp()
        self.cmd = mdc_node_baremetal.MDCBaremetalNodeList(self.app, None)

        class FakeConfig(object):
            def __init__(self, name, region):
                self.name = name
                self.config = {"region_name": region}

        self.cloud1 = FakeConfig("esi", "regionOne")
        self.cloud2 = FakeConfig("esi", "regionTwo")
        self.cloud3 = FakeConfig("esi2", "regionOne")

        self.node = munch.Munch(
            uuid="node_uuid_1",
            name="node1",
            instance_uuid="instance_uuid_1",
            power_state="off",
            provision_state="active",
            maintenance=False,
        )

        self.node2 = munch.Munch(
            uuid="node_uuid_2",
            name="node2",
            instance_uuid="instance_uuid_2",
            power_state="off",
            provision_state="active",
            maintenance=False,
        )

        self.node3 = munch.Munch(
            uuid="node_uuid_3",
            name="node3",
            instance_uuid="instance_uuid_3",
            power_state="off",
            provision_state="active",
            maintenance=False,
        )

        self.node4 = munch.Munch(
            uuid="node_uuid_4",
            name="node4",
            instance_uuid="instance_uuid_4",
            power_state="off",
            provision_state="active",
            maintenance=False,
        )

    @mock.patch("esiclient.v1.mdc.mdc_node_baremetal.openstack.connect")
    @mock.patch(
        "esiclient.v1.mdc.mdc_node_baremetal.openstack.config.loader."
        "OpenStackConfig.get_all_clouds"
    )
    def test_take_action_list(self, mock_config, mock_connect):
        mock_cloud = mock.Mock()
        mock_cloud.list_machines.side_effect = [
            [self.node],
            [self.node2],
            [self.node3, self.node4],
        ]
        mock_connect.return_value = mock_cloud

        mock_config.return_value = [self.cloud1, self.cloud2, self.cloud3]

        arglist = []
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            [
                "Cloud",
                "Region",
                "UUID",
                "Name",
                "Instance UUID",
                "Power State",
                "Provisioning State",
                "Maintenance",
            ],
            [
                [
                    self.cloud1.name,
                    self.cloud1.config["region_name"],
                    "node_uuid_1",
                    "node1",
                    "instance_uuid_1",
                    "off",
                    "active",
                    False,
                ],
                [
                    self.cloud2.name,
                    self.cloud2.config["region_name"],
                    "node_uuid_2",
                    "node2",
                    "instance_uuid_2",
                    "off",
                    "active",
                    False,
                ],
                [
                    self.cloud3.name,
                    self.cloud3.config["region_name"],
                    "node_uuid_3",
                    "node3",
                    "instance_uuid_3",
                    "off",
                    "active",
                    False,
                ],
                [
                    self.cloud3.name,
                    self.cloud3.config["region_name"],
                    "node_uuid_4",
                    "node4",
                    "instance_uuid_4",
                    "off",
                    "active",
                    False,
                ],
            ],
        )
        self.assertEqual(expected, results)
        mock_config.assert_called_once()
        assert mock_cloud.list_machines.call_count == 3

    @mock.patch("esiclient.v1.mdc.mdc_node_baremetal.openstack.connect")
    @mock.patch(
        "esiclient.v1.mdc.mdc_node_baremetal.openstack.config.loader."
        "OpenStackConfig.get_all_clouds"
    )
    def test_take_action_list_cloud(self, mock_config, mock_connect):
        mock_cloud = mock.Mock()
        mock_cloud.list_machines.side_effect = [
            [self.node],
            [self.node2],
            [self.node3, self.node4],
        ]
        mock_connect.return_value = mock_cloud

        mock_config.return_value = [self.cloud1, self.cloud2, self.cloud3]

        arglist = ["--clouds", "esi"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)
        expected = (
            [
                "Cloud",
                "Region",
                "UUID",
                "Name",
                "Instance UUID",
                "Power State",
                "Provisioning State",
                "Maintenance",
            ],
            [
                [
                    self.cloud1.name,
                    self.cloud1.config["region_name"],
                    "node_uuid_1",
                    "node1",
                    "instance_uuid_1",
                    "off",
                    "active",
                    False,
                ],
                [
                    self.cloud2.name,
                    self.cloud2.config["region_name"],
                    "node_uuid_2",
                    "node2",
                    "instance_uuid_2",
                    "off",
                    "active",
                    False,
                ],
            ],
        )
        self.assertEqual(expected, results)
        mock_config.assert_called_once()
        assert mock_cloud.list_machines.call_count == 2

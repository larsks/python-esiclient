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
from unittest import mock

from osc_lib import exceptions

from esiclient.tests.unit import base
from esiclient.v1 import node_console


class TestNodeConsoleConnect(base.TestCommand):
    def setUp(self):
        super(TestNodeConsoleConnect, self).setUp()
        self.cmd = node_console.NodeConsoleConnect(self.app, None)

        self.node_console_1 = {
            "console_enabled": True,
            "console_info": {"type": "socat", "url": "tcp://192.168.1.2:8024"},
        }
        self.node_console_2 = {"console_enabled": False, "console_info": None}

    @mock.patch("esiclient.v1.node_console.os.system", return_value=0, autospec=True)
    def test_take_action(self, mock_system):
        self.app.client_manager.baremetal.node.get_console.return_value = (
            self.node_console_1
        )

        arglist = ["node_console_1"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        result = self.cmd.take_action(parsed_args)

        self.assertEqual(0, result)
        mock_system.assert_called_once

    def test_take_action_no_console_info(self):
        self.app.client_manager.baremetal.node.get_console.return_value = (
            self.node_console_2
        )

        arglist = ["node_console_2"]
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.CommandError,
            "ERROR: No console info for node_console_2. "
            "Run openstack baremetal node console "
            "enable for given node",
            self.cmd.take_action,
            parsed_args,
        )

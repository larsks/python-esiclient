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

import json
import logging
import os

from osc_lib.command import command
from osc_lib import exceptions
from osc_lib.i18n import _


class NodeConsoleConnect(command.Command):
    """Connect the node console"""

    log = logging.getLogger(__name__ + ".NodeConsoleConnect")

    def get_parser(self, prog_name):
        parser = super(NodeConsoleConnect, self).get_parser(prog_name)
        parser.add_argument("node", metavar="<node>", help=_("node"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        node = parsed_args.node

        ironic_client = self.app.client_manager.baremetal

        output = ironic_client.node.get_console(node)

        console_show_output = json.loads(json.dumps(output))

        console_info = console_show_output["console_info"]

        if console_info is None:
            raise exceptions.CommandError(
                "ERROR: No console info for %s. "
                "Run openstack baremetal node console "
                "enable for given node" % node
            )

        else:
            connect_url = console_show_output["console_info"]["url"]
            connect_url = connect_url.replace("//", "")
            return os.system("socat " + connect_url + " -")

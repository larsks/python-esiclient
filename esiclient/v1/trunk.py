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

import logging

from osc_lib.command import command
from osc_lib import exceptions
from osc_lib.i18n import _

from esiclient import utils


class List(command.Lister):
    """List existing trunk ports and subports"""

    log = logging.getLogger(__name__ + ".List")

    def get_parser(self, prog_name):
        parser = super(List, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        neutron_client = self.app.client_manager.network
        trunks = neutron_client.trunks()
        networks = list(neutron_client.networks())
        networks_dict = {n.id: n for n in networks}

        data = []
        for trunk in trunks:
            trunk_port = neutron_client.get_port(trunk.port_id)
            network_names, port_names, _ = utils.get_full_network_info_from_port(
                trunk_port, neutron_client, networks_dict
            )
            data.append([trunk.name, "\n".join(port_names), "\n".join(network_names)])

        return ["Trunk", "Port", "Network"], data


class Create(command.ShowOne):
    """Create trunk port with subports"""

    log = logging.getLogger(__name__ + ".Create")

    def get_parser(self, prog_name):
        parser = super(Create, self).get_parser(prog_name)
        parser.add_argument("name", metavar="<name>", help=_("Name of trunk"))
        parser.add_argument(
            "--native-network",
            metavar="<native_network>",
            help=_("Name or UUID of the native network"),
        )
        parser.add_argument(
            "--tagged-networks",
            default=[],
            dest="tagged_networks",
            action="append",
            metavar="<tagged_networks",
            help=_("Name or UUID of tagged network"),
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        neutron_client = self.app.client_manager.network

        trunk_name = parsed_args.name
        network = neutron_client.find_network(parsed_args.native_network)
        tagged_networks = parsed_args.tagged_networks

        trunk, trunk_port = utils.create_trunk(
            neutron_client, trunk_name, network, tagged_networks
        )

        return ["Trunk", "Port", "Sub Ports"], [
            trunk.name,
            trunk_port.name,
            trunk.sub_ports,
        ]


class AddNetwork(command.ShowOne):
    """Add tagged network"""

    log = logging.getLogger(__name__ + ".AddNetwork")

    def get_parser(self, prog_name):
        parser = super(AddNetwork, self).get_parser(prog_name)
        parser.add_argument("name", metavar="<name>", help=_("Name of trunk"))
        parser.add_argument(
            "--tagged-networks",
            default=[],
            dest="tagged_networks",
            action="append",
            metavar="<tagged_networks",
            help=_("Name or UUID of tagged network"),
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        tagged_networks = parsed_args.tagged_networks

        if len(tagged_networks) == 0:
            raise exceptions.CommandError("ERROR: no networks specified")

        neutron_client = self.app.client_manager.network
        trunk = neutron_client.find_trunk(parsed_args.name)

        if trunk is None:
            raise exceptions.CommandError(
                "ERROR: no trunk named {0}".format(parsed_args.name)
            )

        sub_ports = []
        for tagged_network_name in tagged_networks:
            tagged_network = neutron_client.find_network(tagged_network_name)

            if tagged_network is None:
                raise exceptions.CommandError(
                    "ERROR: no network named {0}".format(tagged_network_name)
                )

            sub_port_name = utils.get_port_name(
                tagged_network.name, prefix=trunk.name, suffix="sub-port"
            )
            sub_port = utils.get_or_create_port(
                sub_port_name, tagged_network, neutron_client
            )
            sub_ports.append(
                {
                    "port_id": sub_port.id,
                    "segmentation_type": "vlan",
                    "segmentation_id": tagged_network.provider_segmentation_id,
                }
            )

        trunk = neutron_client.add_trunk_subports(trunk.id, sub_ports)

        return ["Trunk", "Sub Ports"], [trunk.name, trunk.sub_ports]


class RemoveNetwork(command.ShowOne):
    """Remove tagged network"""

    log = logging.getLogger(__name__ + ".RemoveNetwork")

    def get_parser(self, prog_name):
        parser = super(RemoveNetwork, self).get_parser(prog_name)
        parser.add_argument("name", metavar="<name>", help=_("Name of trunk"))
        parser.add_argument(
            "--tagged-networks",
            default=[],
            dest="tagged_networks",
            action="append",
            metavar="<tagged_networks",
            help=_("Name or UUID of tagged network"),
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        tagged_networks = parsed_args.tagged_networks

        if len(tagged_networks) == 0:
            raise exceptions.CommandError("ERROR: no networks specified")

        neutron_client = self.app.client_manager.network
        trunk = neutron_client.find_trunk(parsed_args.name)

        if trunk is None:
            raise exceptions.CommandError(
                "ERROR: no trunk named {0}".format(parsed_args.name)
            )

        sub_ports = []
        for tagged_network_name in tagged_networks:
            sub_port_name = utils.get_port_name(
                tagged_network_name, prefix=trunk.name, suffix="sub-port"
            )

            sub_port = neutron_client.find_port(sub_port_name)
            if not sub_port:
                raise exceptions.CommandError(
                    "ERROR: {1} is not attached to {0}".format(
                        trunk.name, tagged_network_name
                    )
                )
            sub_ports.append(
                {
                    "port_id": sub_port.id,
                }
            )

        trunk = neutron_client.delete_trunk_subports(trunk.id, sub_ports)
        for sub_port in sub_ports:
            neutron_client.delete_port(sub_port["port_id"])

        return ["Trunk", "Sub Ports"], [trunk.name, trunk.sub_ports]


class Delete(command.Command):
    """Delete trunk port and subports"""

    log = logging.getLogger(__name__ + ".Delete")

    def get_parser(self, prog_name):
        parser = super(Delete, self).get_parser(prog_name)
        parser.add_argument("name", metavar="<name>", help=_("Name of trunk"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        neutron_client = self.app.client_manager.network
        trunk = neutron_client.find_trunk(parsed_args.name)

        if trunk is None:
            raise exceptions.CommandError(
                "ERROR: no trunk named {0}".format(parsed_args.name)
            )

        utils.delete_trunk(neutron_client, trunk)

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
from osc_lib.i18n import _

from esi.lib import nodes

from esiclient import utils


class List(command.Lister):
    """List networks attached to node"""

    log = logging.getLogger(__name__ + ".List")

    def get_parser(self, prog_name):
        parser = super(List, self).get_parser(prog_name)
        parser.add_argument(
            '--node',
            dest='node',
            metavar='<node>',
            help=_("Filter by this node (name or UUID).")
        )
        parser.add_argument(
            '--network',
            dest='network',
            metavar='<network>',
            help=_("Filter by this network (name or UUID).")
        )
        parser.add_argument(
            '--long',
            default=False,
            help=_("Show detailed information."),
            action='store_true')
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        node_networks = nodes.network_list(
            self.app.client_manager.sdk_connection,
            parsed_args.node,
            parsed_args.network
        )

        data = []
        for node_network in node_networks:
            for node_port in node_network['network_info']:
                node_name = node_network['node'].name
                node_uuid = node_network['node'].id
                mac_address = node_port['baremetal_port'].address
                baremetal_port_uuid = node_port['baremetal_port'].id

                network_port_name = None
                network_port_uuid = None
                trunk_uuid = None
                network_names = None
                network_uuids = None
                fixed_ips = None
                floating_network = None
                floating_network_uuid = None
                floating_ip = None
                floating_ip_uuid = None

                if node_port['networks']:
                    if len(node_port['network_ports']):
                        primary_port = node_port['network_ports'][0]
                        network_port_name = getattr(primary_port, 'name')
                        network_port_uuid = getattr(primary_port, 'id')
                        if getattr(primary_port, 'trunk_details'):
                            trunk_uuid = getattr(
                                primary_port, 'trunk_details')['trunk_id']

                    parent_network = node_port['networks']['parent']
                    trunk_networks = node_port['networks']['trunk'] or []

                    network_names = '\n'.join([
                        utils.get_network_display_name(network)
                        for network in [parent_network] + trunk_networks
                        if network is not None
                    ]) or None
                    network_uuids = '\n'.join([
                        network.id
                        for network in [parent_network] + trunk_networks
                        if network is not None
                    ]) or None

                    fixed_ips = '\n'.join([','.join([
                        ip['ip_address'] for ip in port.fixed_ips])
                        for port in node_port['network_ports']]) or None

                    if node_port['networks']['floating']:
                        floating_network = utils.get_network_display_name(
                            node_port['networks']['floating'])
                        floating_network_uuid = \
                            node_port['networks']['floating'].id

                        pfwd_ports = ['%s:%s' % (
                            pfwd.internal_port,
                            pfwd.external_port)
                            for pfwd in node_port['port_forwardings']]

                        floating_ip = \
                            node_port['floating_ip'].floating_ip_address
                        if len(pfwd_ports):
                            floating_ip += ' (%s)' % ','.join(pfwd_ports)
                        floating_ip_uuid = \
                            node_port['floating_ip'].id

                row = [
                    node_name,
                    mac_address,
                    network_port_name,
                    network_names,
                    fixed_ips,
                    floating_network,
                    floating_ip,
                ]
                if parsed_args.long:
                    row.extend(
                        [
                            node_uuid,
                            baremetal_port_uuid,
                            network_port_uuid,
                            trunk_uuid,
                            network_uuids,
                            floating_network_uuid,
                            floating_ip_uuid,
                        ]
                    )
                data.append(row)

        headers = [
            "Node",
            "MAC Address",
            "Port",
            "Network",
            "Fixed IP",
            "Floating Network",
            "Floating IP",
        ]
        if parsed_args.long:
            headers.extend(
                [
                    "Node UUID",
                    "Bare Metal Port UUID",
                    "Network Port UUID",
                    "Trunk UUID",
                    "Network UUID",
                    "Floating Network UUID",
                    "Floating IP UUID",
                ]
            )

        return headers, data


class Attach(command.ShowOne):
    """Attach network to node"""

    log = logging.getLogger(__name__ + ".Attach")

    def get_parser(self, prog_name):
        parser = super(Attach, self).get_parser(prog_name)
        parser.add_argument(
            "node",
            metavar="<node>",
            help=_("Name or UUID of the node"))
        parser.add_argument(
            "--network",
            metavar="<network>",
            help=_("Name or UUID of the network"))
        parser.add_argument(
            '--port',
            dest='port',
            metavar='<port>',
            help=_("Attach to this neutron port (name or UUID).")
        )
        parser.add_argument(
            '--trunk',
            dest='trunk',
            metavar='<trunk>',
            help=_("Attach to this trunk's (name or UUID) parent port.")
        )
        parser.add_argument(
            '--mac-address',
            dest='mac_address',
            metavar='<mac address>',
            help=_("Attach to this mac address.")
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        attach_info = {}

        if parsed_args.network:
            attach_info['network'] = parsed_args.network
        if parsed_args.port:
            attach_info['port'] = parsed_args.port
        if parsed_args.trunk:
            attach_info['trunk'] = parsed_args.trunk
        if parsed_args.mac_address:
            attach_info['mac_address'] = parsed_args.mac_address

        result = nodes.network_attach(
            self.app.client_manager.sdk_connection,
            parsed_args.node,
            attach_info
        )

        return ["Node", "MAC Address", "Port", "Network", "Fixed IP"], \
            [result['node'].name, result['ports'][0].mac_address,
             '\n'.join([port.name for port in result['ports']]),
             '\n'.join([network.name for network in result['networks']]),
             '\n'.join([ip['ip_address'] for port in result['ports']
                        for ip in port.fixed_ips])]


class Detach(command.Command):
    """Detach network from node"""

    log = logging.getLogger(__name__ + ".Detach")

    def get_parser(self, prog_name):
        parser = super(Detach, self).get_parser(prog_name)
        parser.add_argument(
            "node",
            metavar="<node>",
            help=_("Name or UUID of the node"))
        parser.add_argument(
            "--port",
            metavar="<port>",
            help=_("Name or UUID of the port"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        nodes.network_detach(
            self.app.client_manager.sdk_connection,
            parsed_args.node,
            parsed_args.port
        )

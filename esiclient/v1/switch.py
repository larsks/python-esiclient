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


class ListVLAN(command.Lister):
    """List VLANs"""

    log = logging.getLogger(__name__ + ".ListVLAN")

    def get_parser(self, prog_name):
        parser = super(ListVLAN, self).get_parser(prog_name)
        parser.add_argument("switch", metavar="<switch>", help=_("Switch"))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        switch = parsed_args.switch

        ironic_client = self.app.client_manager.baremetal
        neutron_client = self.app.client_manager.network

        ports = list(
            (
                port
                for port in ironic_client.port.list(detail=True)
                if port.local_link_connection.get("switch_info") == switch
            )
        )
        networks = list(neutron_client.networks(provider_network_type="vlan"))
        neutron_ports = list(neutron_client.ports())

        # create neutron port mapping for subports
        subnp_np_map = {}
        for np in neutron_ports:
            if np.trunk_details:
                sub_nps = np.trunk_details["sub_ports"]
                for sub_np in sub_nps:
                    subnp_np_map[sub_np["port_id"]] = np.id

        data = []
        for network in networks:
            switch_ports = []
            subnet_id = next(iter(network.subnet_ids), None)
            if subnet_id:
                nps = (
                    np
                    for np in neutron_ports
                    if next(iter(np.fixed_ips), None).get("subnet_id", None)
                    == subnet_id
                )
                for np in nps:
                    # if this is a subport, get the parent port
                    # as that has the mapping to the switchport
                    search_np_id = subnp_np_map.get(np.id, np.id)
                    port = next(
                        (
                            port
                            for port in ports
                            if port.internal_info.get("tenant_vif_port_id", None)
                            == search_np_id
                        ),
                        None,
                    )
                    if port:
                        switch_ports.append(port.local_link_connection.get("port_id"))
            data.append([network.provider_segmentation_id, switch_ports])

        return ["VLAN", "Ports"], data


class ListSwitchPort(command.Lister):
    """List Switch Ports"""

    log = logging.getLogger(__name__ + ".ListSwitchPort")

    def get_parser(self, prog_name):
        parser = super(ListSwitchPort, self).get_parser(prog_name)
        parser.add_argument("switch", metavar="<switch>", help=_("Switch"))
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        switch = parsed_args.switch

        ironic_client = self.app.client_manager.baremetal
        neutron_client = self.app.client_manager.network

        ports = list(
            (
                port
                for port in ironic_client.port.list(detail=True)
                if port.local_link_connection.get("switch_info") == switch
            )
        )
        neutron_ports = list(neutron_client.ports())
        networks = list(neutron_client.networks())
        networks_dict = {n.id: n for n in networks}

        data = []
        for port in ports:
            switchport = port.local_link_connection.get("port_id")
            network_names = []
            np = None
            np_id = port.internal_info.get("tenant_vif_port_id", None)
            if np_id:
                np = next((np for np in neutron_ports if np.id == np_id), None)
            if np:
                network_names, _, _ = utils.get_full_network_info_from_port(
                    np, neutron_client, networks_dict
                )
            data.append([switchport, "\n".join(network_names)])
        return ["Port", "VLANs"], data


class List(command.Lister):
    """List Switches"""

    log = logging.getLogger(__name__ + ".List")

    def get_parser(self, prog_name):
        parser = super(List, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        ironic_client = self.app.client_manager.baremetal

        ports = ironic_client.port.list(detail=True)

        data = []
        for port in ports:
            switch = port.local_link_connection.get("switch_info")
            switch_id = port.local_link_connection.get("switch_id")

            if [switch, switch_id] not in data:
                data.append([switch, switch_id])
        return ["Switch Name", "Switch ID"], data


class EnableAccessPort(command.ShowOne):
    """Configure Switchport Access"""

    log = logging.getLogger(__name__ + ".EnableAccessPort")

    def get_parser(self, prog_name):
        parser = super(EnableAccessPort, self).get_parser(prog_name)
        parser.add_argument("switch", metavar="<switch>", help=_("Switch"))
        parser.add_argument("switchport", metavar="<switchport>", help=_("Switchport"))
        parser.add_argument("vlan_id", metavar="<vlan_id>", help=_("VLAN ID"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        switch = parsed_args.switch
        switchport = parsed_args.switchport
        vlan_id = parsed_args.vlan_id

        # get associated port and node
        ironic_client = self.app.client_manager.baremetal
        port = utils.get_baremetal_port_from_switchport(
            switch, switchport, ironic_client
        )
        if not port:
            raise exceptions.CommandError("ERROR: Switchport unknown")
        node = ironic_client.node.get(port.node_uuid)

        # get associated network
        neutron_client = self.app.client_manager.network
        network = utils.get_network_from_vlan(vlan_id, neutron_client)
        if not network:
            raise exceptions.CommandError("ERROR: VLAN ID unknown")

        # attach node to network
        np_name = utils.get_port_name(network.name, prefix=node.name)
        np = utils.get_or_create_port(np_name, network, neutron_client)
        ironic_client.node.vif_attach(node.uuid, np.id)

        return ["Switchport", "VLAN", "Node", "Network"], [
            switchport,
            vlan_id,
            node.name,
            network.name,
        ]


class DisableAccessPort(command.Command):
    """Disable Switchport Access"""

    log = logging.getLogger(__name__ + ".DisableAccessPort")

    def get_parser(self, prog_name):
        parser = super(DisableAccessPort, self).get_parser(prog_name)
        parser.add_argument("switch", metavar="<switch>", help=_("Switch"))
        parser.add_argument("switchport", metavar="<switchport>", help=_("Switchport"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        switch = parsed_args.switch
        switchport = parsed_args.switchport

        ironic_client = self.app.client_manager.baremetal
        port = utils.get_baremetal_port_from_switchport(
            switch, switchport, ironic_client
        )
        if not port:
            raise exceptions.CommandError("ERROR: Switchport unknown")

        np_uuid = port.internal_info.get("tenant_vif_port_id", None)
        if not np_uuid:
            raise exceptions.CommandError("ERROR: No neutron port found for switchport")

        print("Disabling access to {0}".format(switchport))

        ironic_client.node.vif_detach(port.node_uuid, np_uuid)


class EnableTrunkPort(command.ShowOne):
    """Configure Switchport Trunk Access"""

    log = logging.getLogger(__name__ + ".EnableTrunkPort")

    def get_parser(self, prog_name):
        parser = super(EnableTrunkPort, self).get_parser(prog_name)
        parser.add_argument("switch", metavar="<switch>", help=_("Switch"))
        parser.add_argument("switchport", metavar="<switchport>", help=_("Switchport"))
        parser.add_argument("vlan_id", metavar="<vlan_id>", help=_("VLAN ID"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        switch = parsed_args.switch
        switchport = parsed_args.switchport
        vlan_id = parsed_args.vlan_id

        # get associated port and node
        ironic_client = self.app.client_manager.baremetal
        port = utils.get_baremetal_port_from_switchport(
            switch, switchport, ironic_client
        )
        if not port:
            raise exceptions.CommandError("ERROR: Switchport unknown")
        node = ironic_client.node.get(port.node_uuid)

        # get associated network
        neutron_client = self.app.client_manager.network
        network = utils.get_network_from_vlan(vlan_id, neutron_client)
        if not network:
            raise exceptions.CommandError("ERROR: VLAN ID unknown")

        # create trunk
        trunk_name = utils.get_switch_trunk_name(switch, switchport)
        trunk_port_name = utils.get_port_name(
            network.name, prefix=trunk_name, suffix="trunk-port"
        )
        trunk_port = utils.get_or_create_port(trunk_port_name, network, neutron_client)
        neutron_client.create_trunk(
            name=trunk_name,
            port_id=trunk_port.id,
        )

        # attach node to network
        ironic_client.node.vif_attach(node.uuid, trunk_port.id)

        return ["Switchport", "VLAN", "Node", "Network", "Trunk"], [
            switchport,
            vlan_id,
            node.name,
            network.name,
            trunk_name,
        ]


class AddTrunkVLAN(command.ShowOne):
    """Add VLAN to Trunk"""

    log = logging.getLogger(__name__ + ".AddTrunkVlan")

    def get_parser(self, prog_name):
        parser = super(AddTrunkVLAN, self).get_parser(prog_name)
        parser.add_argument("switch", metavar="<switch>", help=_("Switch"))
        parser.add_argument("switchport", metavar="<switchport>", help=_("Switchport"))
        parser.add_argument("vlan_id", metavar="<vlan_id>", help=_("VLAN ID"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        switch = parsed_args.switch
        switchport = parsed_args.switchport
        vlan_id = parsed_args.vlan_id

        # get associated port and node
        ironic_client = self.app.client_manager.baremetal
        port = utils.get_baremetal_port_from_switchport(
            switch, switchport, ironic_client
        )
        if not port:
            raise exceptions.CommandError("ERROR: Switchport unknown")
        node = ironic_client.node.get(port.node_uuid)

        # get associated network
        neutron_client = self.app.client_manager.network
        network = utils.get_network_from_vlan(vlan_id, neutron_client)
        if not network:
            raise exceptions.CommandError("ERROR: VLAN ID unknown")

        # find trunk
        trunk_name = utils.get_switch_trunk_name(switch, switchport)
        trunk = neutron_client.find_trunk(trunk_name)
        if trunk is None:
            raise exceptions.CommandError(
                "ERROR: no trunk named {0}".format(trunk_name)
            )

        # attach network to trunk
        sub_port_name = utils.get_port_name(
            network.name, prefix=trunk_name, suffix="sub-port"
        )
        sub_port = utils.get_or_create_port(sub_port_name, network, neutron_client)
        neutron_client.add_trunk_subports(
            trunk.id,
            [
                {
                    "port_id": sub_port.id,
                    "segmentation_type": "vlan",
                    "segmentation_id": vlan_id,
                }
            ],
        )

        return ["Switchport", "VLAN", "Node", "Network", "Trunk"], [
            switchport,
            vlan_id,
            node.name,
            network.name,
            trunk_name,
        ]


class RemoveTrunkVLAN(command.ShowOne):
    """Remove VLAN from Trunk"""

    log = logging.getLogger(__name__ + ".RemoveTrunkVlan")

    def get_parser(self, prog_name):
        parser = super(RemoveTrunkVLAN, self).get_parser(prog_name)
        parser.add_argument("switch", metavar="<switch>", help=_("Switch"))
        parser.add_argument("switchport", metavar="<switchport>", help=_("Switchport"))
        parser.add_argument("vlan_id", metavar="<vlan_id>", help=_("VLAN ID"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        switch = parsed_args.switch
        switchport = parsed_args.switchport
        vlan_id = parsed_args.vlan_id

        # get associated port and node
        ironic_client = self.app.client_manager.baremetal
        port = utils.get_baremetal_port_from_switchport(
            switch, switchport, ironic_client
        )
        if not port:
            raise exceptions.CommandError("ERROR: Switchport unknown")
        node = ironic_client.node.get(port.node_uuid)

        # get associated network
        neutron_client = self.app.client_manager.network
        network = utils.get_network_from_vlan(vlan_id, neutron_client)
        if not network:
            raise exceptions.CommandError("ERROR: VLAN ID unknown")

        # find trunk
        trunk_name = utils.get_switch_trunk_name(switch, switchport)
        trunk = neutron_client.find_trunk(trunk_name)
        if trunk is None:
            raise exceptions.CommandError(
                "ERROR: no trunk named {0}".format(trunk_name)
            )

        # remove network from trunk
        sub_port_name = utils.get_port_name(
            network.name, prefix=trunk_name, suffix="sub-port"
        )
        sub_port = neutron_client.find_port(sub_port_name)
        if not sub_port:
            raise exceptions.CommandError(
                "ERROR: {1} is not attached to {0}".format(network.name, trunk.name)
            )
        trunk = neutron_client.delete_trunk_subports(
            trunk.id,
            [
                {
                    "port_id": sub_port.id,
                }
            ],
        )

        return ["Switchport", "VLAN", "Node", "Network", "Trunk"], [
            switchport,
            vlan_id,
            node.name,
            network.name,
            trunk_name,
        ]


class DisableTrunkPort(command.Command):
    """Disable Trunk Access"""

    log = logging.getLogger(__name__ + ".DisableTrunkPort")

    def get_parser(self, prog_name):
        parser = super(DisableTrunkPort, self).get_parser(prog_name)
        parser.add_argument("switch", metavar="<switch>", help=_("Switch"))
        parser.add_argument("switchport", metavar="<switchport>", help=_("Switchport"))

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        switch = parsed_args.switch
        switchport = parsed_args.switchport

        ironic_client = self.app.client_manager.baremetal
        port = utils.get_baremetal_port_from_switchport(
            switch, switchport, ironic_client
        )
        if not port:
            raise exceptions.CommandError("ERROR: Switchport unknown")

        # find trunk
        neutron_client = self.app.client_manager.network
        trunk_name = utils.get_switch_trunk_name(switch, switchport)
        trunk = neutron_client.find_trunk(trunk_name)
        if trunk is None:
            raise exceptions.CommandError(
                "ERROR: no trunk named {0}".format(trunk_name)
            )

        print("Disabling trunk for {0}".format(switchport))
        ironic_client.node.vif_detach(port.node_uuid, trunk.port_id)

        port_ids_to_delete = [sub_port["port_id"] for sub_port in trunk.sub_ports]
        port_ids_to_delete.append(trunk.port_id)

        neutron_client.delete_trunk(trunk.id)
        for port_id in port_ids_to_delete:
            neutron_client.delete_port(port_id)

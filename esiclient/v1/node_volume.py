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

from datetime import datetime
import logging

from osc_lib.command import command
from osc_lib import exceptions
from osc_lib.i18n import _
from oslo_utils import uuidutils

from esiclient import utils


AVAILABLE = "available"
ACTIVE = "active"


class Attach(command.ShowOne):
    """Attach volume to node"""

    log = logging.getLogger(__name__ + ".Attach")

    def get_parser(self, prog_name):
        parser = super(Attach, self).get_parser(prog_name)
        parser.add_argument(
            "node", metavar="<node>", help=_("Name or UUID of the node")
        )
        parser.add_argument(
            "volume", metavar="<volume>", help=_("Name or UUID of the volume")
        )
        parser.add_argument(
            "--network", metavar="<network>", help=_("Name or UUID of the network")
        )
        parser.add_argument(
            "--port", dest="port", metavar="<port>", help=_("Name or UUID of the port")
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        node_uuid = parsed_args.node
        volume_uuid = parsed_args.volume

        if parsed_args.network and parsed_args.port:
            raise exceptions.CommandError("ERROR: Specify only one of network or port")
        if not parsed_args.network and not parsed_args.port:
            raise exceptions.CommandError(
                "ERROR: You must specify either network or port"
            )

        ironic_client = self.app.client_manager.baremetal
        neutron_client = self.app.client_manager.network
        cinder_client = self.app.client_manager.volume

        if parsed_args.network:
            network = neutron_client.find_network(parsed_args.network)
            port = None
        elif parsed_args.port:
            port = neutron_client.find_port(parsed_args.port)

        node = ironic_client.node.get(node_uuid)
        if uuidutils.is_uuid_like(volume_uuid):
            volume = cinder_client.volumes.get(volume_uuid)
        else:
            volume = cinder_client.volumes.find(name=volume_uuid)

        # check node state
        if node.provision_state != AVAILABLE:
            raise exceptions.CommandError(
                "ERROR: Node {0} must be in the available state".format(node.name)
            )

        # check volume state
        if volume.status != AVAILABLE:
            raise exceptions.CommandError(
                "ERROR: Volume {0} must be in the available state".format(volume.name)
            )

        # check node ports
        baremetal_ports = ironic_client.port.list(node=node_uuid, detail=True)
        has_free_port = False
        for bp in baremetal_ports:
            if "tenant_vif_port_id" not in bp.internal_info:
                has_free_port = True
                break

        if not has_free_port:
            raise exceptions.CommandError(
                "ERROR: Node {0} has no free ports".format(node.name)
            )

        # set baremetal node storage interface and capabilities
        node_update = [
            {
                "path": "/instance_info/storage_interface",
                "value": "cinder",
                "op": "add",
            },
            {
                "path": "/instance_info/capabilities",
                "value": '{"iscsi_boot": "True"}',
                "op": "add",
            },
        ]
        ironic_client.node.update(node_uuid, node_update)

        # delete old volume connectors; create new one
        vcs = ironic_client.volume_connector.list(
            node=node_uuid,
        )
        for vc in vcs:
            ironic_client.volume_connector.delete(vc.uuid)
        connector_id = "iqn.%s.org.openstack.%s" % (
            datetime.now().strftime("%Y-%m"),
            uuidutils.generate_uuid(),
        )
        ironic_client.volume_connector.create(
            node_uuid=node.uuid,
            type="iqn",
            connector_id=connector_id,
        )

        # create volume target if needed
        vts = [
            vt.volume_id
            for vt in ironic_client.volume_target.list(
                node=node_uuid, fields=["volume_id"]
            )
        ]
        if volume.id not in vts:
            ironic_client.volume_target.create(
                node_uuid=node.uuid,
                volume_id=volume.id,
                volume_type="iscsi",
                boot_index=0,
            )

        # attach node to storage network
        if not port:
            # create port if needed
            port_name = utils.get_port_name(
                network.name, prefix=node.name, suffix="volume"
            )
            port = utils.get_or_create_port(port_name, network, neutron_client)

        ironic_client.node.vif_attach(node_uuid, port.id)

        # deploy
        ironic_client.node.set_provision_state(node_uuid, ACTIVE)

        return ["Node", "Volume"], [node.name, volume.name]

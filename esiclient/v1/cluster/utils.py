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

from esiclient import utils


ESI_CLUSTER_UUID = "esi_cluster_uuid"
ESI_TRUNK_UUID = "esi_trunk_uuid"
ESI_PORT_UUID = "esi_port_uuid"
ESI_FIP_UUID = "esi_fip_uuid"


class ESIOrchestrationException(Exception):
    pass


def set_node_cluster_info(ironic_client, node_uuid, cluster_dict):
    node_update = []
    for key, value in cluster_dict.items():
        node_update.append({"path": "/extra/%s" % key, "value": value, "op": "add"})
    ironic_client.node.update(node_uuid, node_update)


def clean_cluster_node(ironic_client, neutron_client, node):
    extra = node.extra

    node_extra_update = []
    node_extra_update.append({"path": "/extra/esi_cluster_uuid", "op": "remove"})

    if ESI_PORT_UUID in extra:
        port_uuid = extra[ESI_PORT_UUID]
        print("   * deleting port %s" % port_uuid)
        neutron_client.delete_port(port_uuid)
        node_extra_update.append({"path": "/extra/esi_port_uuid", "op": "remove"})
    if ESI_TRUNK_UUID in extra:
        trunk_uuid = extra[ESI_TRUNK_UUID]
        print("   * deleting trunk %s" % trunk_uuid)
        trunk = neutron_client.find_trunk(trunk_uuid)
        if trunk:
            utils.delete_trunk(neutron_client, trunk)
            node_extra_update.append({"path": "/extra/esi_trunk_uuid", "op": "remove"})
    if ESI_FIP_UUID in extra:
        fip_uuid = extra[ESI_FIP_UUID]
        print("   * deleting fip %s" % fip_uuid)
        neutron_client.delete_ip(fip_uuid)
        node_extra_update.append({"path": "/extra/esi_fip_uuid", "op": "remove"})

    ironic_client.node.update(node.uuid, node_extra_update)
    ironic_client.node.set_provision_state(node.uuid, "deleted")

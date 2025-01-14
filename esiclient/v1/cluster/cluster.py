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

import concurrent.futures
import json
import logging

from osc_lib.command import command
from osc_lib.i18n import _

from oslo_utils import uuidutils

from esiclient import utils as esi_utils
from esiclient.v1.cluster import utils


class List(command.Lister):
    """List ESI clusters"""

    log = logging.getLogger(__name__ + ".List")

    def get_parser(self, prog_name):
        parser = super(List, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        ironic_client = self.app.client_manager.baremetal

        nodes = ironic_client.node.list(fields=["uuid", "name", "extra"])

        cluster_dict = {}
        for node in nodes:
            extra = node.extra
            # only look at nodes that specify a cluster UUID
            if utils.ESI_CLUSTER_UUID in extra:
                cluster_uuid = extra[utils.ESI_CLUSTER_UUID]
                esi_extra = {}
                for key in extra:
                    # only display 'extra' attributes set by ESI
                    if key.startswith("esi") and key != utils.ESI_CLUSTER_UUID:
                        esi_extra[key] = extra[key]
                if cluster_uuid not in cluster_dict:
                    cluster_dict[cluster_uuid] = {}
                cluster_dict[cluster_uuid][node.name] = esi_extra

        cluster_info = []
        for cluster_uuid in cluster_dict:
            node_info = []
            extra_info = []
            for node in cluster_dict[cluster_uuid]:
                node_info.append(node)
                extra_info.append(str(cluster_dict[cluster_uuid][node]))
            cluster_info.append(
                [cluster_uuid, "\n".join(node_info), "\n".join(extra_info)]
            )

        return ["Cluster", "Node", "Associated"], cluster_info


class Orchestrate(command.Lister):
    """Orchestrate an ESI cluster"""

    log = logging.getLogger(__name__ + ".Orchestrate")

    PROVISIONING_METHODS = ["image", "image_url"]
    AVAILABLE_STATE = "available"

    def get_parser(self, prog_name):
        parser = super(Orchestrate, self).get_parser(prog_name)
        parser.add_argument(
            "cluster_config_file",
            metavar="<cluster_config_file>",
            help=_("File describing the cluster configuration"),
        )

        return parser

    def assign_nodes(self, cluster_config):
        print("ASSIGNING NODES")
        ironic_client = self.app.client_manager.baremetal

        available_nodes = ironic_client.node.list(
            fields=["uuid", "name", "resource_class"],
            provision_state=self.AVAILABLE_STATE,
        )
        node_configs = cluster_config["node_configs"]

        num_configs = len(node_configs)
        config_count = 0
        uuid_node_configs = [
            node_config
            for node_config in node_configs
            if "node_uuids" in node_config["nodes"]
        ]
        non_uuid_node_configs = [
            node_config
            for node_config in node_configs
            if "node_uuids" not in node_config["nodes"]
        ]

        # check configs that specify uuids first
        for node_config in uuid_node_configs:
            config_count += 1
            print(
                "* Assigning nodes for %s out of %s configurations..."
                % (config_count, num_configs)
            )
            node_uuids = node_config["nodes"]["node_uuids"]
            nodes = []
            for node_uuid in node_uuids:
                node = next(
                    (
                        node
                        for node in available_nodes
                        if node.uuid == node_uuid or node.name == node_uuid
                    ),
                    None,
                )
                if not node:
                    raise utils.ESIOrchestrationException(
                        "%s is not an available node" % node_uuid
                    )
                nodes.append(node)
                available_nodes.remove(node)
                print("   * %s" % node.name)
            node_config["nodes"]["ironic_nodes"] = nodes

        # check configs that do not specify uuids
        for node_config in non_uuid_node_configs:
            config_count += 1
            print(
                "* Assigning nodes for %s out of %s configurations..."
                % (config_count, num_configs)
            )
            num_nodes = int(node_config["nodes"]["num_nodes"])
            resource_class = node_config["nodes"]["resource_class"]
            nodes = []
            count = 0
            for node in available_nodes:
                if count >= num_nodes:
                    break
                if node.resource_class == resource_class:
                    nodes.append(node)
                    count += 1
            if count < num_nodes:
                raise utils.ESIOrchestrationException(
                    "Cannot find %s free %s nodes" % (num_nodes, resource_class)
                )
            for node in nodes:
                available_nodes.remove(node)
                print("   * %s" % node.name)
            node_config["nodes"]["ironic_nodes"] = nodes

        print("NODE ASSIGNMENT COMPLETE")
        return

    def get_port_from_network_config(self, node, network_config):
        network_uuid = network_config.get("network_uuid", None)
        if not network_uuid:
            raise utils.ESIOrchestrationException("Must specify a network")

        neutron_client = self.app.client_manager.network
        network = neutron_client.find_network(network_uuid)

        if "tagged_network_uuids" in network_config:
            tagged_networks = network_config["tagged_network_uuids"]
            trunk_name = "esi-%s-trunk" % node.name
            trunk, port = esi_utils.create_trunk(
                neutron_client, trunk_name, network, tagged_networks
            )
            # need to refresh port information after trunk is created
            port = neutron_client.find_port(port.id)
            print("* Using trunk port %s" % trunk_name)
        else:
            trunk = None
            port_name = "esi-%s-%s" % (node.name, network.name)
            port = esi_utils.get_or_create_port(port_name, network, neutron_client)
            print("* Using port %s" % port_name)
        return port, trunk

    def provision_node(self, node, provisioning_type, node_config, cluster_uuid):
        glance_client = self.app.client_manager.image
        ironic_client = self.app.client_manager.baremetal
        neutron_client = self.app.client_manager.network

        cluster_dict = {utils.ESI_CLUSTER_UUID: cluster_uuid}

        network_config = node_config["network"]

        # create network port
        port, trunk = self.get_port_from_network_config(node, network_config)
        if trunk:
            cluster_dict[utils.ESI_TRUNK_UUID] = trunk.id
        else:
            cluster_dict[utils.ESI_PORT_UUID] = port.id

        # provision
        if provisioning_type == "image":
            image = glance_client.find_image(node_config["provisioning"]["image_uuid"])
            ssh_key = node_config["provisioning"].get("ssh_key", None)
            if ssh_key is None:
                raise utils.ESIOrchestrationException(
                    "ssh_key must be specified for image provisioning"
                )
            print("* Provisioning node %s with image %s" % (node.name, image.name))
            esi_utils.provision_node_with_image(
                node.uuid, node.resource_class, port.id, image.id, ssh_key
            )
        elif provisioning_type == "image_url":
            url = node_config["provisioning"].get("url", None)
            if url is None:
                raise utils.ESIOrchestrationException(
                    "url must be specified for image URL provisioning"
                )
            print("* Provisioning node %s from url %s" % (node.name, url))
            esi_utils.boot_node_from_url(node.uuid, url, port.id, ironic_client)

        if "fip_network_uuid" in network_config:
            print(
                "* Assigning floating IP to node %s on port %s" % (node.name, port.name)
            )
            fip_network = neutron_client.find_network(
                network_config["fip_network_uuid"]
            )
            fip = esi_utils.get_or_assign_port_floating_ip(
                port, fip_network, neutron_client
            )
            cluster_dict[utils.ESI_FIP_UUID] = fip.id

        utils.set_node_cluster_info(ironic_client, node.uuid, cluster_dict)

        return node, port

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        cluster_config_file = parsed_args.cluster_config_file
        with open(cluster_config_file) as f:
            cluster_config = json.load(f)

        self.assign_nodes(cluster_config)

        print("")

        print("PROVISIONING NODES")
        cluster_uuid = uuidutils.generate_uuid()
        node_configs = cluster_config["node_configs"]
        futures = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for node_config in node_configs:
                provisioning_type = node_config["provisioning"]["provisioning_type"]
                if provisioning_type not in self.PROVISIONING_METHODS:
                    raise utils.ESIOrchestrationException(
                        "Unknown provisioning method %s" % provisioning_type
                    )
                nodes = node_config["nodes"]["ironic_nodes"]
                for node in nodes:
                    future = executor.submit(
                        self.provision_node,
                        node,
                        provisioning_type,
                        node_config,
                        cluster_uuid,
                    )
                    futures.append(future)
        print("NODE PROVISIONING COMPLETE")

        data = []
        neutron_client = self.app.client_manager.network
        floating_ips = list(neutron_client.ips())
        networks = list(neutron_client.networks())
        networks_dict = {n.id: n for n in networks}
        for future in futures:
            node, port = future.result()
            network_names, _, fixed_ips = esi_utils.get_full_network_info_from_port(
                port, neutron_client, networks_dict
            )
            floating_ip_addresses, floating_network_names = esi_utils.get_floating_ip(
                port.id, floating_ips, networks_dict
            )
            data.append(
                [
                    node.name,
                    port.name,
                    "\n".join(network_names),
                    "\n".join(fixed_ips),
                    "\n".join(floating_network_names)
                    if floating_network_names
                    else None,
                    "\n".join(floating_ip_addresses) if floating_ip_addresses else None,
                ]
            )

        return [
            "Node",
            "Port",
            "Network",
            "Fixed IP",
            "Floating Network",
            "Floating IP",
        ], data


class Undeploy(command.Command):
    """Undeploy a cluster from ESI nodes"""

    log = logging.getLogger(__name__ + ".Undeploy")

    def get_parser(self, prog_name):
        parser = super(Undeploy, self).get_parser(prog_name)

        parser.add_argument(
            "cluster_uuid", metavar="<cluster_uuid>", help=_("Cluster UUID")
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        cluster_uuid = parsed_args.cluster_uuid

        print("STARTING UNDEPLOY for CLUSTER %s" % cluster_uuid)

        ironic_client = self.app.client_manager.baremetal
        neutron_client = self.app.client_manager.network

        nodes = ironic_client.node.list(fields=["uuid", "name", "extra"])
        cluster_found = False
        for node in nodes:
            extra = node.extra
            if extra.get(utils.ESI_CLUSTER_UUID, None) == cluster_uuid:
                cluster_found = True
                print("* Node %s" % node.name)
                utils.clean_cluster_node(ironic_client, neutron_client, node)

        if cluster_found:
            print("UNDEPLOY COMPLETE")
            print("-----------------")
            print("* node cleaning will take a while to complete")
            print(
                "* run `openstack baremetal node list` to see if"
                " they are in the `available` state"
            )
        else:
            print("No cluster with UUID %s found" % cluster_uuid)

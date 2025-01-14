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

import openstack
from osc_lib.command import command
from osc_lib.i18n import _


class MDCBaremetalNodeList(command.Lister):
    """List baremetal nodes from multiple OpenStack instances"""

    log = logging.getLogger(__name__ + ".List")
    auth_required = False

    def get_parser(self, prog_name):
        parser = super(MDCBaremetalNodeList, self).get_parser(prog_name)
        parser.add_argument(
            "--clouds",
            dest="clouds",
            metavar="<clouds>",
            nargs="+",
            help=_("Specify the cloud to use from clouds.yaml."),
        )

        return parser

    def take_action(self, parsed_args):
        columns = [
            "Cloud",
            "Region",
            "UUID",
            "Name",
            "Instance UUID",
            "Power State",
            "Provisioning State",
            "Maintenance",
        ]
        data = []

        cloud_regions = openstack.config.loader.OpenStackConfig().get_all_clouds()
        if parsed_args.clouds:
            cloud_regions = filter(
                lambda c: c.name in parsed_args.clouds, cloud_regions
            )
        for c in cloud_regions:
            nodes = openstack.connect(
                cloud=c.name, region=c.config["region_name"]
            ).list_machines()
            for n in nodes:
                data.append(
                    [
                        c.name,
                        c.config["region_name"],
                        n.uuid,
                        n.name,
                        n.instance_uuid,
                        n.power_state,
                        n.provision_state,
                        n.maintenance,
                    ]
                )

        return columns, data

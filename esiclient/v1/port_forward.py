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

import argparse
import logging
import ipaddress
import re

from dataclasses import dataclass
from enum import Enum

from osc_lib.command import command
from osc_lib.i18n import _  # noqa
from typing import override

LOG = logging.getLogger(__name__)

re_port_spec = re.compile(
    r"(?:(?P<ext_port>\d+):)?(?P<int_port>\d+)(?:/(?P<protocol>\w+))?"
)


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


@dataclass
class PortSpec:
    """Represent a port forwarding from an external port to an internal port"""

    int_port: int
    ext_port: int
    protocol: Protocol = Protocol.TCP

    def __str__(self):
        return f"{self.ext_port}:{self.int_port}/{self.protocol}"

    def __post_init__(self):
        """Apply defaults and validate attributes"""

        if self.ext_port is None:
            self.ext_port = self.int_port
        if self.protocol is None:
            self.protocol = Protocol.TCP

        self.int_port = int(self.int_port)
        self.ext_port = int(self.ext_port)
        self.protocol = Protocol(self.protocol)

        for port in [self.int_port, self.ext_port]:
            if port not in range(0, 65536):
                raise ValueError(f"port {port} out of range")

    @classmethod
    def from_spec(cls, spec: str):
        """Parse a port specifiction of the form [<external_port>:]<internal_port>[/<protocol>]"""

        match = re_port_spec.match(spec)
        if not match:
            raise ValueError("invalid port forward specification")

        return cls(**match.groupdict())


class AddressOrPortArg:
    """Handle a command line argument that can be either an ip address or a port name/id"""

    def __init__(self, cli):
        self.app = cli.app

    def __call__(self, value):
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            port = self.app.client_manager.sdk_connection.network.find_port(value)
            if port is None:
                raise ValueError("invalid port specification")
            return port

    def __repr__(self):
        return "ip address, port name, or port id"


class AddressOrNetworkArg:
    """Handle a command line argument that can be either an ip address or a network name/id"""

    def __init__(self, cli):
        self.app = cli.app

    def __call__(self, value):
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            network = self.app.client_manager.sdk_connection.network.find_network(value)
            if network is None:
                raise ValueError("invalid network name")
            return network

    def __repr__(self):
        return "ip address, network name, or network id"


class NetworkArg:
    """Handle a command line arguments that specifies a network name or id"""

    def __init__(self, cli):
        self.app = cli.app

    def __call__(self, value):
        network = self.app.client_manager.sdk_connection.network.find_network(value)
        if network is None:
            raise ValueError("invalid network name")
        return network

    def __repr__(self):
        return "network name or id"


class SubnetArg:
    """Handle a command line argumenta that specifies a subnet name or id"""

    def __init__(self, cli):
        self.app = cli.app

    def __call__(self, value):
        subnet = self.app.client_manager.sdk_connection.network.find_subnet(value)
        if subnet is None:
            raise ValueError("invalid subnet name")
        return subnet

    def __repr__(self):
        return "subnet name or id"


class NetworkOpsMixin:
    def find_floating_ip(self, address):
        connection = self.app.client_manager.sdk_connection
        if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            # we were given an ip address, so find the matching floating ip
            fip = connection.network.find_ip(str(address))
            if fip is None:
                raise KeyError(f"unable to find floating ip {address}")
            return fip

        raise ValueError("invalid external ip address")

    def find_or_create_floating_ip(self, address):
        connection = self.app.client_manager.sdk_connection
        try:
            return self.find_floating_ip(address)
        except ValueError:
            # we were given a network, so attempt to create a floating ip
            fip = connection.network.create_ip(floating_network_id=address.id)

        return fip

    def find_port(self, address):
        connection = self.app.client_manager.sdk_connection
        if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            # see if there exists a port with the given internal ip
            ports = list(connection.network.ports(fixed_ips=f"ip_address={address}"))

            # error out if we find multiple matches
            if len(ports) > 1:
                raise ValueError(f"found multiple ports matching address {address}")

            # if there was a single port, use it
            if len(ports) == 1:
                return ports[0]

            raise KeyError(f"unable to find port with address {address}")
        else:
            # we already have a port, so just return it
            return address

    def find_or_create_port(
        self, address, internal_ip_network=None, internal_ip_subnet=None
    ):
        connection = self.app.client_manager.sdk_connection
        try:
            return self.find_port(address)
        except KeyError:
            # we need to create a port, which means we need to know the appropriate internal network
            if internal_ip_network is None:
                if internal_ip_subnet is None:
                    raise ValueError(
                        "unable to create a port because --internal-ip-network is unset"
                    )
                internal_network_id = internal_ip_subnet.network_id
            else:
                internal_network_id = internal_ip_network.id

            # if we were given a subnet name, use it, otherwise search through subnets for an appropriate match
            if internal_ip_subnet:
                subnet = internal_ip_subnet
            else:
                for subnet in connection.network.subnets(
                    network_id=internal_network_id,
                ):
                    if subnet.ip_version != address.version:
                        continue
                    cidr = ipaddress.ip_network(subnet.cidr)
                    if address in cidr:
                        break
                else:
                    raise KeyError(f"unable to find a subnet for address {address}")

            return connection.network.create_port(
                network_id=internal_network_id,
                fixed_ips=[{"subnet_id": subnet.id, "ip_address": str(address)}],
            )


class PortForwardListerCommand(command.Lister):
    @override
    def take_action(self, parsed_args: argparse.Namespace):
        forwards = self._take_action(parsed_args)

        return [
            "ID",
            "Internal Port",
            "External Port",
            "Protocol",
            "Internal IP",
            "External IP",
        ], [
            [
                fwd[1].id,
                fwd[1].internal_port,
                fwd[1].external_port,
                fwd[1].protocol,
                fwd[1].internal_ip_address,
                fwd[0].floating_ip_address,
            ]
            for fwd in forwards
        ]


class Create(PortForwardListerCommand, NetworkOpsMixin):
    """Create a port forward from a floating ip to an internal address."""

    @override
    def get_parser(self, prog_name: str):
        parser = super().get_parser(prog_name)

        parser.add_argument(
            "--description", "-d", help="Description to apply to port forwards"
        )

        parser.add_argument(
            "--internal-ip-network",
            type=NetworkArg(self),
            help=_("Network from which to allocate ports for internal ips"),
        )
        parser.add_argument(
            "--internal-ip-subnet",
            type=SubnetArg(self),
            help=_("Subnet from which to allocate ports for internal ips"),
        )
        parser.add_argument("--port", "-p", type=PortSpec.from_spec, action="append")
        parser.add_argument(
            "internal_ip_descriptor",
            type=AddressOrPortArg(self),
            help="ip address, port name, or port uuid",
        )
        parser.add_argument(
            "external_ip_descriptor",
            type=AddressOrNetworkArg(self),
            help="ip address or network name",
        )

        return parser

    def _take_action(self, parsed_args: argparse.Namespace):
        forwards = []

        fip = self.find_or_create_floating_ip(parsed_args.external_ip_descriptor)
        internal_port = self.find_or_create_port(
            parsed_args.internal_ip_descriptor,
            internal_ip_network=parsed_args.internal_ip_network,
            internal_ip_subnet=parsed_args.internal_ip_subnet,
        )

        if isinstance(
            parsed_args.internal_ip_descriptor,
            (ipaddress.IPv4Address, ipaddress.IPv6Address),
        ):
            internal_ip_address = str(parsed_args.internal_ip_descriptor)
        else:
            # if we were given a port name, always pick the first fixed ip. if the user
            # wants to forward to a specific address, they should specify the address
            # rather than the port.
            internal_ip_address = internal_port.fixed_ips[0]["ip_address"]

        for port in parsed_args.port:
            fwd = self.app.client_manager.sdk_connection.network.create_floating_ip_port_forwarding(
                fip,
                description=parsed_args.description,
                internal_ip_address=internal_ip_address,
                internal_port=port.int_port,
                internal_port_id=internal_port.id,
                external_port=port.ext_port,
                protocol=port.protocol,
            )
            forwards.append((fip, fwd))

        return forwards


class Delete(PortForwardListerCommand, NetworkOpsMixin):
    """Delete a port forward from a floating ip to an internal address."""

    @override
    def get_parser(self, prog_name: str):
        parser = super().get_parser(prog_name)

        parser.add_argument("--port", "-p", type=PortSpec.from_spec, action="append")
        parser.add_argument(
            "internal_ip_descriptor",
            type=AddressOrPortArg(self),
            help="ip address, port name, or port uuid",
        )
        parser.add_argument(
            "external_ip_descriptor",
            type=ipaddress.ip_address,
            help="floating ip address",
        )

        return parser

    def _take_action(self, parsed_args: argparse.Namespace):
        forwards = []

        fip = self.find_floating_ip(parsed_args.external_ip_descriptor)
        internal_port = self.find_port(parsed_args.internal_ip_descriptor)

        if isinstance(
            parsed_args.internal_ip_descriptor,
            (ipaddress.IPv4Address, ipaddress.IPv6Address),
        ):
            internal_ip_address = str(parsed_args.internal_ip_descriptor)
        else:
            # if we were given a port name, always pick the first fixed ip. if the user
            # wants to forward to a specific address, they should specify the address
            # rather than the port.
            internal_ip_address = internal_port.fixed_ips[0]["ip_address"]

        for port in parsed_args.port:
            for fwd in self.app.client_manager.sdk_connection.network.floating_ip_port_forwardings(
                fip
            ):
                if (
                    fwd.external_port == port.ext_port
                    and fwd.internal_ip_address == internal_ip_address
                    and fwd.internal_port == port.int_port
                ):
                    forwards.append((fip, fwd))
                    break
            else:
                raise KeyError(f"could not find port forwarding matching {port}")

        for fip, fwd in forwards:
            self.app.client_manager.sdk_connection.network.delete_floating_ip_port_forwarding(
                fip, fwd
            )

        return forwards


class Purge(PortForwardListerCommand, NetworkOpsMixin):
    """Purge all port forwards associated with a floating ip address."""

    @override
    def get_parser(self, prog_name: str):
        parser = super().get_parser(prog_name)

        parser.add_argument(
            "floating_ips",
            type=ipaddress.ip_address,
            nargs="*",
            help=_("List of floating ips from which to remove port forwardings"),
        )

        return parser

    def _take_action(self, parsed_args: argparse.Namespace):
        forwards = []
        for ipaddr in parsed_args.floating_ips:
            fip = self.app.client_manager.sdk_connection.network.find_ip(str(ipaddr))
            forwards.extend(
                (fip, fwd)
                for fwd in self.app.client_manager.sdk_connection.network.floating_ip_port_forwardings(
                    fip
                )
            )

        for fip, fwd in forwards:
            self.app.client_manager.sdk_connection.network.delete_floating_ip_port_forwarding(
                fip, fwd
            )

        return forwards

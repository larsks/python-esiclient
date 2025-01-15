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
from enum import StrEnum

from osc_lib.exceptions import CommandError
from osc_lib.command import command
from osc_lib.i18n import _  # noqa
from typing import override

LOG = logging.getLogger(__name__)

re_ipv4_address = r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
re_forward_spec = re.compile(
    rf"""
    (?P<internal_ip>{re_ipv4_address}):
    (?P<internal_port>\d+):
    (?P<external_ip>{re_ipv4_address})
    (?::(?P<external_port>\d+))?
    (?:/(?P<protocol>\w+))?
""",
    re.VERBOSE,
)


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


@dataclass
class PortForward:
    internal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    internal_port: int
    external_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    external_port: int | None = None
    protocol: Protocol = Protocol.TCP

    def __post_init__(self):
        """Validate field values."""
        if self.external_port is None:
            self.external_port = self.internal_port

        if self.protocol is None:
            self.protocol = Protocol.TCP

        self.internal_ip = ipaddress.ip_address(self.internal_ip)
        self.external_ip = ipaddress.ip_address(self.external_ip)
        self.internal_port = int(self.internal_port)
        self.external_port = int(self.external_port)
        self.protocol = Protocol(self.protocol)

        for port in [self.internal_port, self.external_port]:
            if port not in range(0, 65536):
                raise ValueError(f"port {port} out of range")

    @classmethod
    def from_spec(cls, spec: str):
        match = re_forward_spec.match(spec)
        if not match:
            raise ValueError("invalid forward specification")

        return cls(**match.groupdict())


class Create(command.Lister):
    """Create a port forward from a floating ip to an internal address."""

    @override
    def get_parser(self, prog_name: str):
        parser = super().get_parser(prog_name)

        parser.add_argument(
            "--internal-ip-network",
            help=_("Network from which to allocate ports for internal ips"),
        )
        parser.add_argument(
            "--internal-ip-subnet",
            help=_("Subnet from which to allocate ports for internal ips"),
        )
        parser.add_argument(
            "--external-ip-network",
            default="external",
            help=_("Network from which to allocate floating ips"),
        )
        parser.add_argument(
            "fwdspec",
            nargs="+",
            help="One or more forwarding specifications in the form <internal_ip>:<internal_port>:<external_ip>[:<external_port>][/<protocol>]",
        )

        return parser

    @override
    def take_action(self, parsed_args: argparse.Namespace):
        forwards = []
        for spec in parsed_args.fwdspec:
            parsed_spec = PortForward.from_spec(spec)

            fip = self.app.client_manager.sdk_connection.network.find_ip(
                str(parsed_spec.external_ip)
            )
            if fip is None:
                raise CommandError(
                    f"unable to find floating ip {parsed_spec.external_ip}"
                )

            internal_port = find_or_create_port(
                self.app.client_manager.sdk_connection,
                str(parsed_spec.internal_ip),
                internal_ip_network=parsed_args.internal_ip_network,
                internal_ip_subnet=parsed_args.internal_ip_subnet,
            )
            LOG.debug("using port %s", internal_port)

            LOG.info(
                "create port forward %s:%s -> %s:%s",
                parsed_spec.internal_ip,
                parsed_spec.internal_port,
                fip.floating_ip_address,
                parsed_spec.external_port,
            )

            fwd = self.app.client_manager.sdk_connection.network.create_floating_ip_port_forwarding(
                fip,
                internal_ip_address=str(parsed_spec.internal_ip),
                internal_port=parsed_spec.internal_port,
                internal_port_id=internal_port.id,
                external_port=parsed_spec.external_port,
                protocol=parsed_spec.protocol.value,
            )
            forwards.append((fip, fwd))

        return ["ID", "Port", "Protocol", "Internal IP", "External IP"], [
            [
                fwd[1].id,
                fwd[1].internal_port,
                fwd[1].protocol,
                fwd[1].internal_ip_address,
                fwd[0].floating_ip_address,
            ]
            for fwd in forwards
        ]


class Delete(command.Lister):
    """Delete a port forward from a floating ip to an internal address."""

    @override
    def get_parser(self, prog_name: str):
        parser = super().get_parser(prog_name)

        parser.add_argument(
            "fwdspec",
            nargs="+",
            help="One or more forwarding specifications in the form <internal_ip>:<internal_port>:<external_ip>[:<external_port>][/<protocol>]",
        )

        return parser

    @override
    def take_action(self, parsed_args: argparse.Namespace):
        forwards = []
        for spec in parsed_args.fwdspec:
            parsed_spec = PortForward.from_spec(spec)
            print(parsed_spec)
            fip = self.app.client_manager.sdk_connection.network.find_ip(
                str(parsed_spec.external_ip)
            )
            for fwd in self.app.client_manager.sdk_connection.network.floating_ip_port_forwardings(
                fip
            ):
                print(fwd)
                if (
                    fwd.external_port == parsed_spec.external_port
                    and fwd.internal_ip_address == str(parsed_spec.internal_ip)
                    and fwd.internal_port == parsed_spec.internal_port
                ):
                    forwards.append((parsed_spec.external_ip, fip, fwd))
                    break
            else:
                raise ValueError(f"could not find port forwarding matching {spec}")

        for ipaddr, fip, fwd in forwards:
            LOG.info(
                "delete port forward %s %s:%d -> %s:%d",
                fwd.id,
                fwd.internal_ip_address,
                fwd.internal_port,
                fip.floating_ip_address,
                fwd.external_port,
            )
            self.app.client_manager.sdk_connection.network.delete_floating_ip_port_forwarding(
                fip, fwd
            )

        return ["ID", "Port", "Protocol", "Internal IP", "External IP"], [
            [
                fwd[2].id,
                fwd[2].internal_port,
                fwd[2].protocol,
                fwd[2].internal_ip_address,
                fwd[0],
            ]
            for fwd in forwards
        ]


class Purge(command.Lister):
    """Purge all port forwards associated with a floating ip address."""

    @override
    def get_parser(self, prog_name: str):
        parser = super().get_parser(prog_name)

        parser.add_argument(
            "floating_ips",
            nargs="*",
            help=_("List of floating ips from which to remove port forwardings"),
        )

        return parser

    @override
    def take_action(self, parsed_args: argparse.Namespace):
        forwards = []
        for ipaddr in parsed_args.floating_ips:
            fip = self.app.client_manager.sdk_connection.network.find_ip(ipaddr)
            forwards.extend(
                (ipaddr, fip, fwd)
                for fwd in self.app.client_manager.sdk_connection.network.floating_ip_port_forwardings(
                    fip
                )
            )

        for ipaddr, fip, fwd in forwards:
            LOG.info(
                "delete port forward %s %s:%d -> %s:%d",
                fwd.id,
                fwd.internal_ip_address,
                fwd.internal_port,
                fip.floating_ip_address,
                fwd.external_port,
            )
            self.app.client_manager.sdk_connection.network.delete_floating_ip_port_forwarding(
                fip, fwd
            )

        return ["ID", "Port", "Protocol", "Internal IP", "External IP"], [
            [
                fwd[2].id,
                fwd[2].internal_port,
                fwd[2].protocol,
                fwd[2].internal_ip_address,
                fwd[0],
            ]
            for fwd in forwards
        ]


def find_or_create_floating_ip(
    connection,
    ipaddr: str | None = None,
    external_ip_network: str | None = None,
):
    if ipaddr is not None:
        fip = connection.network.find_ip(ipaddr)
        if fip is not None:
            return fip

    if external_ip_network is None:
        raise ValueError(
            "unable to create floating ip because --external-ip-network is unset"
        )

    network = connection.network.find_network(external_ip_network)
    if network is None:
        raise ValueError("unable to find floating ip network {external_ip_network}")

    fip = connection.network.create_ip(
        floating_network_id=network.id, floating_ip_address=ipaddr
    )
    if fip is None:
        raise ValueError(
            f"failed to create floating ip in network {external_ip_network}"
        )

    return fip


def find_or_create_port(
    connection,
    ipaddr: str,
    internal_ip_network: str | None = None,
    internal_ip_subnet: str | None = None,
):
    port = next(connection.network.ports(fixed_ips=f"ip_address={ipaddr}"), None)
    if port is not None:
        LOG.info(f"using existing port {port.id} for address {ipaddr}")
        return port

    if internal_ip_network is None:
        raise ValueError(
            "unable to create a port because --internal-ip-network is unset"
        )

    network = connection.network.find_network(internal_ip_network)
    if network is None:
        raise ValueError(f"unable to find network {internal_ip_network}")

    if internal_ip_subnet:
        subnet = connection.network.find_subnet(internal_ip_subnet)
        if subnet is None:
            raise ValueError(f"unable to find subnet {internal_ip_subnet}")
    else:
        _ipaddr = ipaddress.ip_address(ipaddr)
        for subnet in connection.network.subnets(network_id=network.id):
            if subnet.ip_version != _ipaddr.version:
                continue
            cidr = ipaddress.ip_network(subnet.cidr)
            if _ipaddr in cidr:
                break
        else:
            raise ValueError(f"unable to find a subnet for address {ipaddr}")

    LOG.debug(f"using subnet {subnet.id} for address service_namesipaddr")

    port = connection.network.create_port(
        network_id=network.id,
        fixed_ips=[{"subnet_id": subnet.id, "ip_address": ipaddr}],
    )
    LOG.info(f"create port {port.id} in subnet {subnet.name} for address {ipaddr}")
    return port

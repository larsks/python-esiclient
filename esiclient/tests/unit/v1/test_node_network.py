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
#

import mock

from openstack import exceptions

from esiclient.tests.unit import base
from esiclient.tests.unit import utils
from esiclient.v1 import node_network


class TestList(base.TestCommand):

    def setUp(self):
        super(TestList, self).setUp()

        self.port1 = utils.create_mock_object({
            "id": "port_uuid_1",
            "node_uuid": "11111111-2222-3333-4444-aaaaaaaaaaaa",
            "address": "aa:aa:aa:aa:aa:aa",
            "internal_info": {'tenant_vif_port_id': 'neutron_port_uuid_1'}
        })
        self.port2 = utils.create_mock_object({
            "id": "port_uuid_2",
            "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
            "address": "bb:bb:bb:bb:bb:bb",
            "internal_info": {}
        })
        self.port3 = utils.create_mock_object({
            "id": "port_uuid_3",
            "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
            "address": "cc:cc:cc:cc:cc:cc",
            "internal_info": {'tenant_vif_port_id': 'neutron_port_uuid_2'}
        })
        self.port4 = utils.create_mock_object({
            "id": "port_uuid_4",
            "node_uuid": "11111111-2222-3333-4444-bbbbbbbbbbbb",
            "address": "dd:dd:dd:dd:dd:dd",
            "internal_info": {'tenant_vif_port_id': 'neutron_port_uuid_4'}
        })
        self.port5 = utils.create_mock_object({
            'id': 'port_uuid_5',
            'node_uuid': '11111111-2222-3333-4444-bbbbbbbbbbbb',
            'address': 'ee:ee:ee:ee:ee:ee',
            'internal_info': {'tenant_vif_port_id': 'neutron_port_uuid_3'}
        })
        self.node1 = utils.create_mock_object({
            "id": "11111111-2222-3333-4444-aaaaaaaaaaaa",
            "name": "node1"
        })
        self.node2 = utils.create_mock_object({
            "id": "11111111-2222-3333-4444-bbbbbbbbbbbb",
            "name": "node2"
        })
        self.network1 = utils.create_mock_object({
            "id": "network_uuid_1",
            "name": "test_network_1"
        })
        self.network2 = utils.create_mock_object({
            "id": "network_uuid_2",
            "name": "test_network_2"
        })
        self.network3 = utils.create_mock_object({
            "id": "network_uuid_3",
            "name": "test_network_3"
        })
        self.neutron_port1 = utils.create_mock_object({
            "id": "neutron_port_uuid_1",
            "network_id": "network_uuid_1",
            "name": "neutron_port_1",
            "fixed_ips": [{"ip_address": "1.1.1.1"}],
            "trunk_details": None
        })
        self.neutron_port2 = utils.create_mock_object({
            "id": "neutron_port_uuid_2",
            "network_id": "network_uuid_1",
            "name": "neutron_port_2",
            "fixed_ips": [{"ip_address": "2.2.2.2"}],
            "trunk_details": None
        })
        self.neutron_port3 = utils.create_mock_object({
            'id': 'neutron_port_uuid_3',
            'network_id': 'network_uuid_3',
            'name': 'neutron_port_3',
            'fixed_ips': [{'ip_address': '3.3.3.3'}],
            'trunk_details': {
                'trunk_id': 'trunk_uuid_1',
                'sub_ports': [
                    {'port_id': 'subport_uuid_1'},
                    {'port_id': 'subport_uuid_2'},
                ]
            }
        })
        self.subport_1 = utils.create_mock_object({
            'id': 'subport_uuid_1',
            'network_id': 'network_uuid_1',
            'name': 'subport_1',
            'fixed_ips': [{'ip_address': '4.4.4.4'}],
            'trunk_details': None
        })
        self.subport_2 = utils.create_mock_object({
            'id': 'subport_uuid_2',
            'network_id': 'network_uuid_2',
            'name': 'subport_2',
            'fixed_ips': [{'ip_address': '5.5.5.5'}],
            'trunk_details': None
        })
        self.floating_network1 = utils.create_mock_object({
            "id": "floating_network_id_1",
            "name": "floating_network_1"
        })
        self.floating_network2 = utils.create_mock_object({
            "id": "floating_network_id_2",
            "name": "floating_network_2"
        })
        self.floating_ip = utils.create_mock_object({
            "id": "floating_ip_uuid_2",
            "floating_ip_address": "8.8.8.8",
            "floating_network_id": "floating_network_id_1",
            "port_id": "neutron_port_uuid_2"
        })
        self.floating_ip_pfw = utils.create_mock_object({
            "id": "floating_ip_uuid_1",
            "floating_ip_address": "9.9.9.9",
            "floating_network_id": "floating_network_id_1",
            "port_id": None
        })
        self.floating_ip2 = utils.create_mock_object({
            'id': 'floating_ip_uuid_3',
            'floating_ip_address': '10.10.10.10',
            'floating_network_id': 'floating_network_id_2',
            'port_id': None
        })
        self.pfw1 = utils.create_mock_object({
            "internal_port": 22,
            "external_port": 22,
            "internal_port_id": "neutron_port_uuid_1"
        })
        self.pfw2 = utils.create_mock_object({
            "internal_port": 23,
            "external_port": 23,
            "internal_port_id": "neutron_port_uuid_1"
        })
        self.pfw3 = utils.create_mock_object({
            "internal_port": 24,
            "external_port": 24,
            "internal_port_id": "neutron_port_uuid_3"
        })

        self.cmd = node_network.List(self.app, None)

    @mock.patch('esiclient.utils.get_network_display_name')
    @mock.patch('esi.lib.nodes.network_list')
    def test_take_action_no_network(self,
                                    mock_network_list,
                                    mock_get_network_display_name):
        mock_network_list.return_value = [
            {
                'node': self.node1,
                'network_info': [
                    {
                        'baremetal_port': self.port1,
                        'network_ports': [],
                        'networks': {
                            'parent': None,
                            'trunk': [],
                            'floating': None,
                        },
                        'floating_ip': None,
                        'port_forwardings': []
                    }
                ]
            }
        ]

        mock_get_network_display_name.\
            side_effect = lambda network: network.name

        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        data = [
            [
                'node1',
                'aa:aa:aa:aa:aa:aa',
                None,
                None,
                None,
                None,
                None,
            ]
        ]

        expected = ["Node", "MAC Address", "Port", "Network", "Fixed IP",
                    "Floating Network", "Floating IP"], data

        self.assertEqual(expected, results)
        mock_get_network_display_name.assert_not_called()

    @mock.patch('esiclient.utils.get_network_display_name')
    @mock.patch('esi.lib.nodes.network_list')
    def test_take_action_multiple_nodes(self,
                                        mock_network_list,
                                        mock_get_network_display_name):
        mock_network_list.return_value = [
            {
                'node': self.node1,
                'network_info': [
                    {
                        'baremetal_port': self.port1,
                        'network_ports': [],
                        'networks': {
                            'parent': None,
                            'trunk': [],
                            'floating': None,
                        },
                        'floating_ip': None,
                        'port_forwardings': []
                    }
                ]
            },
            {
                'node': self.node2,
                'network_info': [
                    {
                        'baremetal_port': self.port3,
                        'network_ports': [self.neutron_port2],
                        'networks': {
                            'parent': self.network1,
                            'trunk': [],
                            'floating': self.floating_network1,
                        },
                        'floating_ip': self.floating_ip,
                        'port_forwardings': []
                    }
                ]
            }
        ]

        mock_get_network_display_name.\
            side_effect = lambda network: network.name

        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        data = [
            [
                'node1',
                'aa:aa:aa:aa:aa:aa',
                None,
                None,
                None,
                None,
                None,
            ],
            [
                'node2',
                'cc:cc:cc:cc:cc:cc',
                'neutron_port_2',
                'test_network_1',
                '2.2.2.2',
                'floating_network_1',
                '8.8.8.8'
            ]
        ]

        expected = ["Node", "MAC Address", "Port", "Network", "Fixed IP",
                    "Floating Network", "Floating IP"], data

        self.assertEqual(expected, results)
        mock_get_network_display_name.assert_has_calls([
            mock.call(self.network1),
            mock.call(self.floating_network1),
        ])

    @mock.patch('esiclient.utils.get_network_display_name')
    @mock.patch('esi.lib.nodes.network_list')
    def test_take_action_multiple_ports(self,
                                        mock_network_list,
                                        mock_get_network_display_name):
        mock_network_list.return_value = [
            {
                'node': self.node2,
                'network_info': [
                    {
                        'baremetal_port': self.port2,
                        'network_ports': [],
                        'networks': {
                            'parent': None,
                            'trunk': [],
                            'floating': None
                        },
                        'floating_ip': None,
                        'port_forwardings': []
                    },
                    {
                        'baremetal_port': self.port3,
                        'network_ports': [self.neutron_port2],
                        'networks': {
                            'parent': self.network1,
                            'trunk': [],
                            'floating': self.floating_network1
                        },
                        'floating_ip': self.floating_ip,
                        'port_forwardings': []
                    }
                ]
            }
        ]

        mock_get_network_display_name.\
            side_effect = lambda network: network.name

        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        data = [
            [
                'node2',
                'bb:bb:bb:bb:bb:bb',
                None,
                None,
                None,
                None,
                None,
            ],
            [
                'node2',
                'cc:cc:cc:cc:cc:cc',
                'neutron_port_2',
                'test_network_1',
                '2.2.2.2',
                'floating_network_1',
                '8.8.8.8'
            ]
        ]

        expected = ["Node", "MAC Address", "Port", "Network", "Fixed IP",
                    "Floating Network", "Floating IP"], data

        self.assertEqual(expected, results)
        mock_get_network_display_name.assert_has_calls([
            mock.call(self.network1),
            mock.call(self.floating_network1),
        ])

    @mock.patch('esiclient.utils.get_network_display_name')
    @mock.patch('esi.lib.nodes.network_list')
    def test_take_action_port_forwardings(self,
                                          mock_network_list,
                                          mock_get_network_display_name):
        mock_network_list.return_value = [
            {
                'node': self.node1,
                'network_info': [
                    {
                        'baremetal_port': self.port1,
                        'network_ports': [self.neutron_port1],
                        'networks': {
                            'parent': self.network1,
                            'trunk': [],
                            'floating': self.floating_network1,
                        },
                        'floating_ip': self.floating_ip_pfw,
                        'port_forwardings': [self.pfw1, self.pfw2]
                    }
                ]
            }
        ]

        mock_get_network_display_name.\
            side_effect = lambda network: network.name

        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        data = [
            [
                'node1',
                'aa:aa:aa:aa:aa:aa',
                'neutron_port_1',
                'test_network_1',
                '1.1.1.1',
                'floating_network_1',
                '9.9.9.9 (22:22,23:23)'
            ]
        ]

        expected = ["Node", "MAC Address", "Port", "Network", "Fixed IP",
                    "Floating Network", "Floating IP"], data

        self.assertEqual(expected, results)
        mock_get_network_display_name.assert_has_calls([
            mock.call(self.network1),
            mock.call(self.floating_network1),
        ])

    @mock.patch('esiclient.utils.get_network_display_name')
    @mock.patch('esi.lib.nodes.network_list')
    def test_take_action_trunk(self,
                               mock_network_list,
                               mock_get_network_display_name):
        mock_network_list.return_value = [
            {
                'node': self.node2,
                'network_info': [
                    {
                        'baremetal_port': self.port5,
                        'network_ports': [
                            self.neutron_port3,
                            self.subport_1,
                            self.subport_2
                        ],
                        'networks': {
                            'parent': self.network3,
                            'trunk': [
                                self.network1,
                                self.network2
                            ],
                            'floating': None
                        },
                        'floating_ip': None,
                        'port_forwardings': []
                    }
                ]
            }
        ]

        mock_get_network_display_name.\
            side_effect = lambda network: network.name

        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        data = [
            [
                'node2',
                'ee:ee:ee:ee:ee:ee',
                'neutron_port_3',
                'test_network_3\ntest_network_1\ntest_network_2',
                '3.3.3.3\n4.4.4.4\n5.5.5.5',
                None,
                None
            ]
        ]

        expected = ["Node", "MAC Address", "Port", "Network", "Fixed IP",
                    "Floating Network", "Floating IP"], data

        self.assertEqual(expected, results)
        mock_get_network_display_name.assert_has_calls([
            mock.call(self.network3),
            mock.call(self.network1),
            mock.call(self.network2),
        ])

    @mock.patch('esiclient.utils.get_network_display_name')
    @mock.patch('esi.lib.nodes.network_list')
    def test_take_action(self,
                         mock_network_list,
                         mock_get_network_display_name):
        mock_network_list.return_value = [
            {
                'node': self.node1,
                'network_info': [
                    {
                        'baremetal_port': self.port1,
                        'network_ports': [self.neutron_port1],
                        'networks': {
                            'parent': self.network1,
                            'trunk': [],
                            'floating': self.floating_network1,
                        },
                        'floating_ip': self.floating_ip_pfw,
                        'port_forwardings': [self.pfw1, self.pfw2]
                    }
                ]
            },
            {
                'node': self.node2,
                'network_info': [
                    {
                        'baremetal_port': self.port2,
                        'network_ports': [],
                        'networks': {
                            'parent': None,
                            'trunk': [],
                            'floating': None
                        },
                        'floating_ip': None,
                        'port_forwardings': []
                    },
                    {
                        'baremetal_port': self.port5,
                        'network_ports': [
                            self.neutron_port3,
                            self.subport_1,
                            self.subport_2
                        ],
                        'networks': {
                            'parent': self.network3,
                            'trunk': [
                                self.network1,
                                self.network2
                            ],
                            'floating': self.floating_network2
                        },
                        'floating_ip': self.floating_ip2,
                        'port_forwardings': [self.pfw3]
                    }
                ]
            }
        ]

        mock_get_network_display_name.\
            side_effect = lambda network: network.name

        arglist = []
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        data = [
            [
                'node1',
                'aa:aa:aa:aa:aa:aa',
                'neutron_port_1',
                'test_network_1',
                '1.1.1.1',
                'floating_network_1',
                '9.9.9.9 (22:22,23:23)'
            ],
            [
                'node2',
                'bb:bb:bb:bb:bb:bb',
                None,
                None,
                None,
                None,
                None
            ],
            [
                'node2',
                'ee:ee:ee:ee:ee:ee',
                'neutron_port_3',
                'test_network_3\ntest_network_1\ntest_network_2',
                '3.3.3.3\n4.4.4.4\n5.5.5.5',
                'floating_network_2',
                '10.10.10.10 (24:24)'
            ]
        ]

        expected = ["Node", "MAC Address", "Port", "Network", "Fixed IP",
                    "Floating Network", "Floating IP"], data

        self.assertEqual(expected, results)
        mock_get_network_display_name.assert_has_calls([
            mock.call(self.network1),
            mock.call(self.floating_network1),
            mock.call(self.network3),
            mock.call(self.network1),
            mock.call(self.network2),
            mock.call(self.floating_network2),
        ])

    @mock.patch('esiclient.utils.get_network_display_name')
    @mock.patch('esi.lib.nodes.network_list')
    def test_take_action_long(self,
                              mock_network_list,
                              mock_get_network_display_name):
        mock_network_list.return_value = [
            {
                'node': self.node1,
                'network_info': [
                    {
                        'baremetal_port': self.port1,
                        'network_ports': [self.neutron_port1],
                        'networks': {
                            'parent': self.network1,
                            'trunk': [],
                            'floating': self.floating_network1,
                        },
                        'floating_ip': self.floating_ip_pfw,
                        'port_forwardings': [self.pfw1, self.pfw2]
                    }
                ]
            },
            {
                'node': self.node2,
                'network_info': [
                    {
                        'baremetal_port': self.port2,
                        'network_ports': [],
                        'networks': {
                            'parent': None,
                            'trunk': [],
                            'floating': None
                        },
                        'floating_ip': None,
                        'port_forwardings': []
                    },
                    {
                        'baremetal_port': self.port5,
                        'network_ports': [
                            self.neutron_port3,
                            self.subport_1,
                            self.subport_2
                        ],
                        'networks': {
                            'parent': self.network3,
                            'trunk': [
                                self.network1,
                                self.network2
                            ],
                            'floating': self.floating_network2
                        },
                        'floating_ip': self.floating_ip2,
                        'port_forwardings': [self.pfw3]
                    }
                ]
            }
        ]

        mock_get_network_display_name.\
            side_effect = lambda network: network.name

        arglist = ['--long']
        verifylist = []
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        data = [
                [
                    "node1",
                    "aa:aa:aa:aa:aa:aa",
                    "neutron_port_1",
                    "test_network_1",
                    "1.1.1.1",
                    "floating_network_1",
                    "9.9.9.9 (22:22,23:23)",
                    "11111111-2222-3333-4444-aaaaaaaaaaaa",
                    "port_uuid_1",
                    "neutron_port_uuid_1",
                    None,
                    "network_uuid_1",
                    "floating_network_id_1",
                    "floating_ip_uuid_1",
                ],
                [
                    "node2",
                    "bb:bb:bb:bb:bb:bb",
                    None,
                    None,
                    None,
                    None,
                    None,
                    "11111111-2222-3333-4444-bbbbbbbbbbbb",
                    "port_uuid_2",
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
                [
                    "node2",
                    "ee:ee:ee:ee:ee:ee",
                    "neutron_port_3",
                    "test_network_3\ntest_network_1\ntest_network_2",
                    "3.3.3.3\n4.4.4.4\n5.5.5.5",
                    "floating_network_2",
                    "10.10.10.10 (24:24)",
                    "11111111-2222-3333-4444-bbbbbbbbbbbb",
                    "port_uuid_5",
                    "neutron_port_uuid_3",
                    "trunk_uuid_1",
                    "network_uuid_3\nnetwork_uuid_1\nnetwork_uuid_2",
                    "floating_network_id_2",
                    "floating_ip_uuid_3",
                ],
        ]

        expected = (
            [
                "Node",
                "MAC Address",
                "Port",
                "Network",
                "Fixed IP",
                "Floating Network",
                "Floating IP",
                "Node UUID",
                "Bare Metal Port UUID",
                "Network Port UUID",
                "Trunk UUID",
                "Network UUID",
                "Floating Network UUID",
                "Floating IP UUID",
            ],
            data,
        )

        self.assertEqual(expected, results)
        mock_get_network_display_name.assert_has_calls([
            mock.call(self.network1),
            mock.call(self.floating_network1),
            mock.call(self.network3),
            mock.call(self.network1),
            mock.call(self.network2),
            mock.call(self.floating_network2),
        ])


class TestAttach(base.TestCommand):

    def setUp(self):
        super(TestAttach, self).setUp()
        self.cmd = node_network.Attach(self.app, None)

        self.port1 = utils.create_mock_object({
            "id": "port_uuid_1",
            "node_uuid": "node_uuid_1",
            "address": "aa:aa:aa:aa:aa:aa",
            "internal_info": {'tenant_vif_port_id': 'neutron_port_uuid_1'}
        })
        self.port2 = utils.create_mock_object({
            "id": "port_uuid_2",
            "node_uuid": "node_uuid_1",
            "address": "bb:bb:bb:bb:bb:bb",
            "internal_info": {}
        })
        self.node = utils.create_mock_object({
            "id": "node_uuid_1",
            "name": "node1",
            "provision_state": "active"
        })
        self.node_available = utils.create_mock_object({
            "id": "node_uuid_1",
            "name": "node1",
            "provision_state": "available"
        })
        self.node_manageable = utils.create_mock_object({
            "id": "node_uuid_1",
            "name": "node1",
            "provision_state": "manageable",
            "instance_info": {},
            "driver_info": {'deploy_ramdisk': 'fake-image'},
        })
        self.node_manageable_instance_info = utils.create_mock_object({
            "id": "node_uuid_1",
            "name": "node1",
            "provision_state": "manageable",
            "instance_info": {'image_source': 'fake-image',
                              'capabilities': {}},
            "driver_info": {'deploy_ramdisk': 'fake-image'},
        })
        self.network = utils.create_mock_object({
            "id": "network_uuid",
            "name": "test_network"
        })
        self.neutron_port = utils.create_mock_object({
            "id": "neutron_port_uuid_2",
            "network_id": "network_uuid",
            "name": "node1-port",
            "mac_address": "bb:bb:bb:bb:bb:bb",
            "fixed_ips": [{"ip_address": "2.2.2.2"}],
            "trunk_details": None
        })
        self.trunk = utils.create_mock_object({
            "port_id": self.neutron_port.id,
            "name": "test_trunk"
        })

    @mock.patch('esi.lib.nodes.network_attach')
    def test_take_action_network(self, mock_gfnifp):
        mock_gfnifp.return_value = {
            'node': self.node,
            'ports': [self.neutron_port],
            'networks': [self.network]
        }

        arglist = ['node1', '--network', 'test_network']
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        expected = (
            ["Node", "MAC Address", "Port", "Network", "Fixed IP"],
            ["node1", "bb:bb:bb:bb:bb:bb", "node1-port", "test_network",
             "2.2.2.2"]
        )

        mock_gfnifp.assert_called_once_with(
            self.app.client_manager.sdk_connection,
            'node1',
            {'network': 'test_network'})
        self.assertEqual(expected, results)

    @mock.patch('esi.lib.nodes.network_attach')
    def test_take_action_port(self, mock_gfnifp):
        mock_gfnifp.return_value = {
            'node': self.node,
            'ports': [self.neutron_port],
            'networks': [self.network]
        }

        arglist = ['node_uuid_1', '--port', 'node1-port']
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        expected = (
            ["Node", "MAC Address", "Port", "Network", "Fixed IP"],
            ["node1", "bb:bb:bb:bb:bb:bb", "node1-port", "test_network",
             "2.2.2.2"]
        )

        mock_gfnifp.assert_called_once_with(
            self.app.client_manager.sdk_connection,
            'node_uuid_1',
            {'port': 'node1-port'})
        self.assertEqual(expected, results)

    @mock.patch('esi.lib.nodes.network_attach')
    def test_take_action_port_and_mac_address(self, mock_gfnifp):
        mock_gfnifp.return_value = {
            'node': self.node,
            'ports': [self.neutron_port],
            'networks': [self.network]
        }

        arglist = ['node1', '--port', 'node1-port',
                   '--mac-address', 'bb:bb:bb:bb:bb:bb']
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        expected = (
            ["Node", "MAC Address", "Port", "Network", "Fixed IP"],
            ["node1", "bb:bb:bb:bb:bb:bb", "node1-port", "test_network",
             "2.2.2.2"]
        )

        mock_gfnifp.assert_called_once_with(
            self.app.client_manager.sdk_connection,
            'node1',
            {'port': 'node1-port', 'mac_address': 'bb:bb:bb:bb:bb:bb'}
        )
        self.assertEqual(expected, results)

    @mock.patch('esi.lib.nodes.network_attach')
    def test_take_action_trunk(self, mock_gfnifp):
        mock_gfnifp.return_value = {
            'node': self.node,
            'ports': [self.neutron_port],
            'networks': [self.network]
        }

        arglist = ['node1', '--trunk', 'test_trunk']
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        results = self.cmd.take_action(parsed_args)

        expected = (
            ["Node", "MAC Address", "Port", "Network", "Fixed IP"],
            ["node1", "bb:bb:bb:bb:bb:bb", "node1-port",
             "test_network", "2.2.2.2"]
        )

        mock_gfnifp.assert_called_once_with(
            self.app.client_manager.sdk_connection,
            'node1',
            {'trunk': 'test_trunk'}
        )
        self.assertEqual(expected, results)

    def test_take_action_port_network_and_trunk_exception(self):
        arglist1 = ['node1', '--network', 'test_network', '--port', 'node1']
        arglist2 = ['node1', '--network', 'test_network', '--trunk', 'trunk']
        arglist3 = ['node1', '--port', 'node1', '--trunk', 'trunk']
        verifylist = []

        parsed_args1 = self.check_parser(self.cmd, arglist1, verifylist)
        parsed_args2 = self.check_parser(self.cmd, arglist2, verifylist)
        parsed_args3 = self.check_parser(self.cmd, arglist3, verifylist)

        self.assertRaisesRegex(
            exceptions.InvalidRequest,
            'Specify only one of network, port, or trunk',
            self.cmd.take_action,
            parsed_args1)

        self.assertRaisesRegex(
            exceptions.InvalidRequest,
            'Specify only one of network, port, or trunk',
            self.cmd.take_action,
            parsed_args2)

        self.assertRaisesRegex(
            exceptions.InvalidRequest,
            'Specify only one of network, port, or trunk',
            self.cmd.take_action,
            parsed_args3)

    def test_take_action_no_port_or_network_or_trunk_exception(self):
        arglist = ['node1']
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.assertRaisesRegex(
            exceptions.InvalidRequest,
            'You must specify either network, port, or trunk',
            self.cmd.take_action,
            parsed_args)


class TestDetach(base.TestCommand):

    def setUp(self):
        super(TestDetach, self).setUp()
        self.cmd = node_network.Detach(self.app, None)

        self.node = utils.create_mock_object({
            "id": "node_uuid_1",
            "name": "node1",
            "provision_state": "active"
        })
        self.neutron_port1 = utils.create_mock_object({
            "id": "neutron_port_uuid_1",
            "network_id": "network_uuid",
            "name": "neutron_port_1",
            "mac_address": "bb:bb:bb:bb:bb:bb",
            "fixed_ips": [{"ip_address": "2.2.2.2"}],
            "trunk_details": None
        })

    @mock.patch('esi.lib.nodes.network_detach',
                return_value=True)
    def test_take_action(self, mock_network_detach):
        arglist = ['node1']
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_network_detach.assert_called_once_with(
            self.app.client_manager.sdk_connection,
            'node1',
            None)

    @mock.patch('esi.lib.nodes.network_detach',
                return_value=True)
    def test_take_action_port(self, mock_network_detach):
        arglist = ['node_uuid_1', '--port', 'neutron_port_1']
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        self.cmd.take_action(parsed_args)

        mock_network_detach.assert_called_once_with(
            self.app.client_manager.sdk_connection,
            'node_uuid_1',
            'neutron_port_1')

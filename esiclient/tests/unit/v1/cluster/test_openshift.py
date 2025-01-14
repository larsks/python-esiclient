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

from unittest import mock
from unittest.mock import call
from unittest.mock import patch
import os
from unittest import TestCase

from esiclient.tests.unit import base
from esiclient.tests.unit import utils
from esiclient.v1.cluster import openshift
from esiclient.v1.cluster import utils as cluster_utils


class MockResponse:
    def __init__(self, json_data={}, status_code=200, reason=None):
        self.json_data = json_data
        self.status_code = status_code
        self.reason = reason

    def json(self):
        return self.json_data


class TestCallAssistedInstallerAPI(TestCase):
    @mock.patch("requests.patch", autospec=True)
    @mock.patch("requests.get", autospec=True)
    @mock.patch("requests.post", autospec=True)
    def test_call_assisted_installer_api_post(self, mock_post, mock_get, mock_patch):
        mock_post.return_value = MockResponse()

        openshift.call_assisted_installer_api("test", "post")

        mock_post.assert_called_once_with(
            openshift.BASE_ASSISTED_INSTALLER_URL + "test", headers={}, json=None
        )
        mock_get.assert_not_called
        mock_patch.assert_not_called

    @mock.patch("requests.patch", autospec=True)
    @mock.patch("requests.get", autospec=True)
    @mock.patch("requests.post", autospec=True)
    def test_call_assisted_installer_api_get(self, mock_post, mock_get, mock_patch):
        mock_get.return_value = MockResponse()

        openshift.call_assisted_installer_api("test", "get")

        mock_get.assert_called_once_with(
            openshift.BASE_ASSISTED_INSTALLER_URL + "test", headers={}
        )
        mock_post.assert_not_called
        mock_patch.assert_not_called

    @mock.patch("requests.patch", autospec=True)
    @mock.patch("requests.get", autospec=True)
    @mock.patch("requests.post", autospec=True)
    def test_call_assisted_installer_api_patch(self, mock_post, mock_get, mock_patch):
        mock_patch.return_value = MockResponse()

        openshift.call_assisted_installer_api("test", "patch")

        mock_patch.assert_called_once_with(
            openshift.BASE_ASSISTED_INSTALLER_URL + "test", headers={}, json=None
        )
        mock_get.assert_not_called
        mock_post.assert_not_called

    def test_call_assisted_installer_api_unknown_method(self):
        self.assertRaises(
            openshift.OSAIException,
            openshift.call_assisted_installer_api,
            "test",
            "foo",
        )

    @mock.patch("requests.get", autospec=True)
    def test_call_assisted_installer_api_400(self, mock_get):
        mock_get.return_value = MockResponse(status_code=400, reason="foo")

        self.assertRaises(
            openshift.OSAIException,
            openshift.call_assisted_installer_api,
            "test",
            "get",
        )


class TestWaitForNodes(TestCase):
    @mock.patch("time.sleep", autospec=True)
    @mock.patch(
        "esiclient.v1.cluster.openshift.call_assisted_installer_api", autospec=True
    )
    def test_wait_for_nodes(self, mock_caia, mock_sleep):
        first_response = []
        second_response = [{"status": "pending", "requested_hostname": "host1"}]
        third_response = [
            {"status": "known", "requested_hostname": "host1"},
            {"status": "known", "requested_hostname": "host2"},
        ]
        fourth_response = [
            {"status": "known", "requested_hostname": "host1"},
            {"status": "known", "requested_hostname": "host2"},
            {"status": "pending", "requested_hostname": "host3"},
        ]
        fifth_response = [
            {"status": "known", "requested_hostname": "host1"},
            {"status": "known", "requested_hostname": "host2"},
            {"status": "known", "requested_hostname": "host3"},
        ]

        mock_caia.side_effect = [
            MockResponse(first_response),
            MockResponse(second_response),
            MockResponse(third_response),
            MockResponse(fourth_response),
            MockResponse(fifth_response),
        ]

        openshift.wait_for_nodes("infra-env-id", {}, 3, "known")

        assert mock_caia.call_count == 5
        assert mock_sleep.call_count == 4


class TestOrchestrate(base.TestCommand):
    def setUp(self):
        super(TestOrchestrate, self).setUp()
        self.cmd = openshift.Orchestrate(self.app, None)

        self.cluster_id = "cluster-id"
        self.infra_env_id = "infra-env-id"

        self.node1 = utils.create_mock_object(
            {"uuid": "node_uuid_1", "name": "node1", "provision_state": "available"}
        )
        self.node2 = utils.create_mock_object(
            {"uuid": "node_uuid_2", "name": "node2", "provision_state": "available"}
        )
        self.node3 = utils.create_mock_object(
            {"uuid": "node_uuid_3", "name": "node3", "provision_state": "active"}
        )

        def mock_get_node(name):
            if name == "node1":
                return self.node1
            if name == "node2":
                return self.node2
            if name == "node3":
                return self.node3
            return None

        self.app.client_manager.baremetal.node.get.side_effect = mock_get_node

        self.private_network = utils.create_mock_object(
            {
                "id": "network_uuid_1",
                "name": "private_network",
            }
        )
        self.provisioning_network = utils.create_mock_object(
            {
                "id": "network_uuid_2",
                "name": "provisioning_network",
            }
        )
        self.external_network = utils.create_mock_object(
            {
                "id": "network_uuid_3",
                "name": "external_network",
            }
        )

        def mock_find_network(name):
            if name == "private_network":
                return self.private_network
            if name == "provisioning_network":
                return self.provisioning_network
            if name == "external_network":
                return self.external_network
            return None

        self.app.client_manager.network.find_network.side_effect = mock_find_network

        self.private_subnet = utils.create_mock_object(
            {"id": "subnet_uuid_1", "name": "private_subnet", "cidr": "1.1.1.1/1"}
        )

        def mock_find_subnet(name):
            if name == "private_subnet":
                return self.private_subnet
            return None

        self.app.client_manager.network.find_subnet.side_effect = mock_find_subnet

        self.bm_port1 = utils.create_mock_object(
            {
                "uuid": "bm_port_uuid_1",
                "node_uuid": "node_uuid_1",
                "address": "aa:aa:aa:aa:aa:aa",
                "internal_info": {"tenant_vif_port_id": "port_uuid_1"},
            }
        )
        self.bm_port2 = utils.create_mock_object(
            {
                "uuid": "bm_port_uuid_2",
                "node_uuid": "node_uuid_2",
                "address": "bb:bb:bb:bb:bb:bb",
                "internal_info": {"tenant_vif_port_id": "port_uuid_2"},
            }
        )
        self.bm_port3 = utils.create_mock_object(
            {
                "uuid": "bm_port_uuid_3",
                "node_uuid": "node_uuid_3",
                "address": "cc:cc:cc:cc:cc:cc",
                "internal_info": {"tenant_vif_port_id": "port_uuid_3"},
            }
        )

        def mock_list_ports(node, detail=True):
            if node == "node1":
                return [self.bm_port1]
            if node == "node2":
                return [self.bm_port2]
            if node == "node3":
                return [self.bm_port3]
            return None

        self.app.client_manager.baremetal.port.list.side_effect = mock_list_ports

        self.port1 = utils.create_mock_object(
            {
                "id": "port_uuid_1",
                "network_id": "network_uuid_2",
            }
        )
        self.port2 = utils.create_mock_object(
            {
                "id": "port_uuid_2",
                "network_id": "network_uuid_2",
            }
        )
        self.port3 = utils.create_mock_object(
            {
                "id": "port_uuid_3",
                "network_id": "network_uuid_2",
            }
        )

        def mock_find_port(uuid):
            if uuid == "port_uuid_1":
                return self.port1
            if uuid == "port_uuid_2":
                return self.port2
            if uuid == "port_uuid_3":
                return self.port3
            return None

        self.app.client_manager.network.find_port.side_effect = mock_find_port

        self.app.client_manager.baremetal.node.vif_detach.return_value = None
        self.app.client_manager.baremetal.node.vif_attach.return_value = None
        self.app.client_manager.baremetal.node.vif_set_boot_device.return_value = None

        self.provisioning_port1 = {
            "id": "provisioning_port_uuid_1",
            "network_id": "network_uuid_2",
        }
        self.provisioning_port2 = {
            "id": "provisioning_port_uuid_2",
            "network_id": "network_uuid_2",
        }
        self.provisioning_port3 = {
            "id": "provisioning_port_uuid_3",
            "network_id": "network_uuid_2",
        }

        self.private_port1 = {
            "id": "private_port_uuid_1",
            "network_id": "network_uuid_1",
        }
        self.private_port2 = {
            "id": "private_port_uuid_2",
            "network_id": "network_uuid_1",
        }
        self.private_port3 = {
            "id": "private_port_uuid_3",
            "network_id": "network_uuid_1",
        }

        self.api_port = utils.create_mock_object(
            {
                "id": "api_port_uuid_1",
                "network_id": "network_uuid_1",
            }
        )
        self.apps_port = utils.create_mock_object(
            {
                "id": "apps_port_uuid_1",
                "network_id": "network_uuid_1",
            }
        )

        self.api_fip = utils.create_mock_object({"floating_ip_address": "3.3.3.3"})
        self.apps_fip = utils.create_mock_object({"floating_ip_address": "4.4.4.4"})

    @mock.patch("esiclient.v1.cluster.utils.set_node_cluster_info", autospec=True)
    @mock.patch("esiclient.utils.get_or_assign_port_floating_ip", autospec=True)
    @mock.patch("esiclient.utils.get_or_create_port_by_ip", autospec=True)
    @mock.patch("esiclient.utils.get_or_create_port", autospec=True)
    @mock.patch("esiclient.utils.boot_node_from_url", autospec=True)
    @mock.patch("esiclient.v1.cluster.openshift.wait_for_nodes", autospec=True)
    @mock.patch(
        "esiclient.v1.cluster.openshift.call_assisted_installer_api", autospec=True
    )
    @mock.patch("time.sleep", autospec=True)
    @mock.patch("json.loads", autospec=True)
    @mock.patch("json.load", autospec=True)
    @mock.patch.dict(
        os.environ, {"PULL_SECRET": "pull_secret_file", "API_TOKEN": "api-token"}
    )
    def test_take_action(
        self,
        mock_load,
        mock_loads,
        mock_sleep,
        mock_caia,
        mock_wfn,
        mock_bnfu,
        mock_gocp,
        mock_gocpbi,
        mock_goapfi,
        mock_snci,
    ):
        mock_load.return_value = {
            "cluster_name": "test_cluster",
            "api_vip": "1.1.1.1",
            "ingress_vip": "2.2.2.2",
            "openshift_version": "1",
            "base_dns_domain": "foo.bar",
            "ssh_public_key": "ssh-public-key",
            "external_network_name": "external_network",
            "provisioning_network_name": "provisioning_network",
            "private_network_name": "private_network",
            "private_subnet_name": "private_subnet",
            "nodes": ["node1", "node2", "node3"],
        }
        mock_loads.return_value = "pull_secret_value"
        mock_caia.side_effect = [
            # creating cluster/infra env
            MockResponse({"id": self.cluster_id}),
            MockResponse({"id": self.infra_env_id}),
            # no hosts ready
            MockResponse([]),
            # get boot iso image url
            MockResponse({"url": "this-is-a-url"}),
            # is cluster installing?
            MockResponse({"status": "waiting"}),
            # set machine network cidr
            MockResponse([]),
            # start installing
            MockResponse([]),
            # check installation status
            MockResponse({"status": "installing"}),
            MockResponse({"status": "installed"}),
        ]
        mock_gocp.side_effect = [
            self.provisioning_port1,
            self.provisioning_port2,
            self.private_port1,
            self.private_port2,
            self.private_port3,
        ]
        mock_gocpbi.side_effect = [self.api_port, self.apps_port]
        mock_goapfi.side_effect = [self.api_fip, self.apps_fip]

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            results = self.cmd.take_action(parsed_args)

        expected = (["Endpoint", "IP"], [["API", "3.3.3.3"], ["apps", "4.4.4.4"]])
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer api-token",
        }

        mock_loads.assert_called_once_with("pull_secret_file")
        assert mock_caia.call_count == 9
        mock_caia.assert_has_calls(
            [
                # creating cluster/infra env
                call(
                    "clusters",
                    "post",
                    headers,
                    {
                        "name": "test_cluster",
                        "openshift_version": "1",
                        "high_availability_mode": "Full",
                        "base_dns_domain": "foo.bar",
                        "ssh_public_key": "ssh-public-key",
                        "pull_secret": "pull_secret_value",
                    },
                ),
                call(
                    "infra-envs",
                    "post",
                    headers,
                    {
                        "name": "test_cluster-infra-env",
                        "image_type": "minimal-iso",
                        "cluster_id": "cluster-id",
                        "pull_secret": "pull_secret_value",
                        "openshift_version": "1",
                        "ssh_authorized_key": "ssh-public-key",
                    },
                ),
                # no hosts ready
                call("infra-envs/%s/hosts" % self.infra_env_id, "get", headers),
                # get boot iso image url
                call(
                    "infra-envs/%s/downloads/image-url" % self.infra_env_id,
                    "get",
                    headers,
                ),
                # is cluster installing?
                call("clusters/%s/" % self.cluster_id, "get", headers),
                # set machine network cidr
                call(
                    "clusters/%s" % self.cluster_id,
                    "patch",
                    headers,
                    {
                        "machine_network_cidr": self.private_subnet.cidr,
                        "api_vips": [{"cluster_id": self.cluster_id, "ip": "1.1.1.1"}],
                        "ingress_vips": [
                            {"cluster_id": self.cluster_id, "ip": "2.2.2.2"}
                        ],
                    },
                ),
                # start installing
                call("clusters/%s/actions/install" % self.cluster_id, "post", headers),
                # check installation status
                call("clusters/%s/" % self.cluster_id, "get", headers),
                call("clusters/%s/" % self.cluster_id, "get", headers),
            ]
        )
        assert mock_wfn.call_count == 2
        mock_wfn.assert_has_calls(
            [
                call(self.infra_env_id, headers, 3, "pending-for-input"),
                call(self.infra_env_id, headers, 3, "known"),
            ]
        )
        assert mock_bnfu.call_count == 2
        mock_bnfu.assert_has_calls(
            [
                call(
                    "node1",
                    "this-is-a-url",
                    "provisioning_port_uuid_1",
                    self.app.client_manager.baremetal,
                ),
                call(
                    "node2",
                    "this-is-a-url",
                    "provisioning_port_uuid_2",
                    self.app.client_manager.baremetal,
                ),
            ]
        )
        assert mock_gocp.call_count == 5
        mock_gocp.assert_has_calls(
            [
                call(
                    "esi-node1-provisioning_network",
                    self.provisioning_network,
                    self.app.client_manager.network,
                ),
                call(
                    "esi-node2-provisioning_network",
                    self.provisioning_network,
                    self.app.client_manager.network,
                ),
                call(
                    "esi-node1-private_network",
                    self.private_network,
                    self.app.client_manager.network,
                ),
                call(
                    "esi-node2-private_network",
                    self.private_network,
                    self.app.client_manager.network,
                ),
                call(
                    "esi-node3-private_network",
                    self.private_network,
                    self.app.client_manager.network,
                ),
            ]
        )
        assert mock_gocpbi.call_count == 2
        mock_gocpbi.assert_has_calls(
            [
                call(
                    "1.1.1.1",
                    "test_cluster-api",
                    self.private_network,
                    self.private_subnet,
                    self.app.client_manager.network,
                ),
                call(
                    "2.2.2.2",
                    "test_cluster-apps",
                    self.private_network,
                    self.private_subnet,
                    self.app.client_manager.network,
                ),
            ]
        )
        assert mock_goapfi.call_count == 2
        mock_goapfi.assert_has_calls(
            [
                call(
                    self.api_port,
                    self.external_network,
                    self.app.client_manager.network,
                ),
                call(
                    self.apps_port,
                    self.external_network,
                    self.app.client_manager.network,
                ),
            ]
        )
        self.assertEqual(expected, results)
        mock_snci.assert_has_calls(
            [
                call(
                    self.app.client_manager.baremetal,
                    "node1",
                    {
                        cluster_utils.ESI_CLUSTER_UUID: "cluster-id",
                        cluster_utils.ESI_PORT_UUID: "private_port_uuid_1",
                    },
                ),
                call(
                    self.app.client_manager.baremetal,
                    "node2",
                    {
                        cluster_utils.ESI_CLUSTER_UUID: "cluster-id",
                        cluster_utils.ESI_PORT_UUID: "private_port_uuid_2",
                    },
                ),
                call(
                    self.app.client_manager.baremetal,
                    "node3",
                    {
                        cluster_utils.ESI_CLUSTER_UUID: "cluster-id",
                        cluster_utils.ESI_PORT_UUID: "private_port_uuid_3",
                    },
                ),
            ]
        )

    @mock.patch("json.load", autospec=True)
    @mock.patch.dict(
        os.environ, {"PULL_SECRET": "pull_secret_file", "API_TOKEN": "api-token"}
    )
    def test_take_action_missing_fields(self, mock_load):
        mock_load.return_value = {
            "api_vip": "1.1.1.1",
            "ingress_vip": "2.2.2.2",
            "openshift_version": "1",
            "base_dns_domain": "foo.bar",
            "ssh_public_key": "ssh-public-key",
            "external_network_name": "external_network",
            "provisioning_network_name": "provisioning_network",
            "private_network_name": "private_network",
            "private_subnet_name": "private_subnet",
            "nodes": ["node1", "node2", "node3"],
        }

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            self.assertRaisesRegex(
                cluster_utils.ESIOrchestrationException,
                "Please specify these missing values",
                self.cmd.take_action,
                parsed_args,
            )

    @mock.patch("json.load", autospec=True)
    @mock.patch.dict(os.environ, {"API_TOKEN": "api-token"})
    def test_take_action_missing_pull_secret(self, mock_load):
        mock_load.return_value = {
            "cluster_name": "test_cluster",
            "api_vip": "1.1.1.1",
            "ingress_vip": "2.2.2.2",
            "openshift_version": "1",
            "base_dns_domain": "foo.bar",
            "ssh_public_key": "ssh-public-key",
            "external_network_name": "external_network",
            "provisioning_network_name": "provisioning_network",
            "private_network_name": "private_network",
            "private_subnet_name": "private_subnet",
            "nodes": ["node1", "node2", "node3"],
        }

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            self.assertRaisesRegex(
                cluster_utils.ESIOrchestrationException,
                "Please export PULL_SECRET",
                self.cmd.take_action,
                parsed_args,
            )


class TestUndeploy(base.TestCommand):
    def setUp(self):
        super(TestUndeploy, self).setUp()
        self.cmd = openshift.Undeploy(self.app, None)

        self.api_port = utils.create_mock_object(
            {
                "id": "api_port_uuid_1",
                "network_id": "network_uuid_1",
            }
        )
        self.apps_port = utils.create_mock_object(
            {
                "id": "apps_port_uuid_1",
                "network_id": "network_uuid_1",
            }
        )

        def mock_ports(fixed_ips=None):
            if fixed_ips == "ip_address=1.1.1.1":
                return [self.api_port]
            if fixed_ips == "ip_address=2.2.2.2":
                return [self.apps_port]
            return []

        self.app.client_manager.network.ports.side_effect = mock_ports
        self.app.client_manager.network.delete_port.return_value = None

        self.api_fip = utils.create_mock_object(
            {"id": "fip_uuid_1", "floating_ip_address": "3.3.3.3"}
        )
        self.apps_fip = utils.create_mock_object(
            {"id": "fip_uuid_2", "floating_ip_address": "4.4.4.4"}
        )

        def mock_ips(fixed_ip_address=None):
            if fixed_ip_address == "1.1.1.1":
                return [self.api_fip]
            if fixed_ip_address == "2.2.2.2":
                return [self.apps_fip]
            return []

        self.app.client_manager.network.ips.side_effect = mock_ips
        self.app.client_manager.network.delete_ip.return_value = None

        self.node1 = utils.create_mock_object(
            {
                "uuid": "node_uuid_1",
                "name": "node1",
            }
        )
        self.node2 = utils.create_mock_object(
            {
                "uuid": "node_uuid_2",
                "name": "node2",
            }
        )
        self.node3 = utils.create_mock_object(
            {
                "uuid": "node_uuid_3",
                "name": "node3",
            }
        )

        def mock_get_node(name):
            if name == "node1":
                return self.node1
            if name == "node2":
                return self.node2
            if name == "node3":
                return self.node3
            return None

        self.app.client_manager.baremetal.node.get.side_effect = mock_get_node

    @mock.patch("esiclient.v1.cluster.utils.clean_cluster_node", autospec=True)
    @mock.patch("json.loads", autospec=True)
    @mock.patch("json.load", autospec=True)
    @mock.patch.dict(
        os.environ, {"PULL_SECRET": "pull_secret_file", "API_TOKEN": "api-token"}
    )
    def test_take_action(self, mock_load, mock_loads, mock_ccn):
        mock_load.return_value = {
            "cluster_name": "test_cluster",
            "api_vip": "1.1.1.1",
            "ingress_vip": "2.2.2.2",
            "openshift_version": "1",
            "base_dns_domain": "foo.bar",
            "ssh_public_key": "ssh-public-key",
            "external_network_name": "external_network",
            "provisioning_network_name": "provisioning_network",
            "private_network_name": "private_network",
            "private_subnet_name": "private_subnet",
            "nodes": ["node1", "node2", "node3"],
        }
        mock_loads.return_value = "pull_secret_value"

        arglist = ["config.json"]
        verifylist = []

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        with patch("builtins.open"):
            self.cmd.take_action(parsed_args)

        self.app.client_manager.network.ports.assert_has_calls(
            [call(fixed_ips="ip_address=1.1.1.1"), call(fixed_ips="ip_address=2.2.2.2")]
        )
        self.app.client_manager.network.ips.assert_has_calls(
            [call(fixed_ip_address="1.1.1.1"), call(fixed_ip_address="2.2.2.2")]
        )
        self.app.client_manager.network.delete_ip.assert_has_calls(
            [call("fip_uuid_1"), call("fip_uuid_2")]
        )
        self.app.client_manager.network.delete_port.assert_has_calls(
            [
                call("api_port_uuid_1"),
                call("apps_port_uuid_1"),
            ]
        )
        self.app.client_manager.baremetal.node.get.assert_has_calls(
            [call("node1"), call("node2"), call("node3")]
        )
        mock_ccn.assert_has_calls(
            [
                call(
                    self.app.client_manager.baremetal,
                    self.app.client_manager.network,
                    self.node1,
                ),
                call(
                    self.app.client_manager.baremetal,
                    self.app.client_manager.network,
                    self.node2,
                ),
                call(
                    self.app.client_manager.baremetal,
                    self.app.client_manager.network,
                    self.node3,
                ),
            ]
        )

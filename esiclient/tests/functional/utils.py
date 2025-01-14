#    Copyright (c) 2016 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import time

from tempest.lib.common.utils import data_utils


def kwargs_to_flags(valid_flags, arguments):
    """kwargs to flag helper

    Takes an iterable containing a list of valid flags and a flattened
    kwargs dict containing the flag values received by the function.

    The key for each dict entry should be the name of a valid flag for the
    command being run, with any hyphens in the flag name replaced with
    underscores (e.g. end-time -> end_time). Its corresponding value
    should be a string, True (if that flag is included by itself),
    or None/False to indicate the flag should be excluded.

    Returns a stringified version of kwargs for use with CLI commands.

    """
    flag_string = ""
    for flag in arguments.keys():
        val = arguments[flag]
        if val is not None:
            if flag in valid_flags:
                tmp = " --%s" % flag.replace("_", "-")
                if isinstance(val, str):
                    flag_string += '%s "%s"' % (tmp, val)
                elif isinstance(val, bool):
                    flag_string += tmp if val else ""
                else:
                    raise TypeError(
                        "Invalid value for flag %s, expected \
                                     type 'str' or 'bool' and got type \
                                     '%s'"
                        % (flag, type(val).__name__)
                    )
            else:
                raise NameError("Invalid flag with name %s" % flag)
    return flag_string


def esi_node_network_attach(client, node_ident, port_ident, fail_ok=False):
    client.esi(
        "node network attach", "--port {0}".format(port_ident), node_ident, fail_ok
    )


def esi_node_network_detach(client, node_ident, port_ident, fail_ok=False):
    client.esi(
        "node network detach ", "", "{0} {1}".format(node_ident, port_ident), fail_ok
    )


def esi_node_network_list(client, params="", fail_ok=False):
    output = client.esi("node network list", "{0} -f json".format(params), "", fail_ok)
    return json.loads(output)


def esi_trunk_create(client, native_network_ident, name=None, fail_ok=False):
    if not name:
        name = data_utils.rand_name("trunk")
    output = client.esi(
        "trunk create",
        "--native-network {0} -f json".format(native_network_ident),
        name,
        fail_ok,
    )
    return json.loads(output)


def esi_trunk_delete(client, trunk_ident, fail_ok=False):
    return client.esi("trunk delete", "", trunk_ident, fail_ok)


def esi_trunk_list(client, fail_ok=False):
    output = client.esi("trunk list", "-f json", "", fail_ok)
    return json.loads(output)


def esi_trunk_add_network(client, trunk_ident, tagged_network_ident, fail_ok=False):
    return client.esi(
        "trunk add network",
        "--tagged-networks {0}".format(tagged_network_ident),
        trunk_ident,
        fail_ok,
    )


def esi_trunk_remove_network(client, trunk_ident, tagged_network_ident, fail_ok=False):
    return client.esi(
        "trunk remove network",
        "--tagged-networks {0}".format(tagged_network_ident),
        trunk_ident,
        fail_ok,
    )


def esi_node_volume_attach(client, port_ident, node_ident, volume_ident, fail_ok=False):
    client.esi(
        "node volume attach",
        "--port %s" % port_ident,
        "{0} {1}".format(node_ident, volume_ident),
        fail_ok,
    )
    # wait until target provision state is None
    node = node_show(client, node_ident, fail_ok)
    while node["target_provision_state"] is not None:
        node = node_show(client, node_ident, fail_ok)
        time.sleep(15)


def image_create(
    client,
    image_path,
    name=None,
    visibility="public",
    disk_format="qcow2",
    container_format="bare",
    fail_ok=False,
):
    if not name:
        name = data_utils.rand_name("image")
    output = client.image(
        "create",
        "--{0} --disk-format {1} --container-format {2} --file {3} -f json".format(
            visibility, disk_format, container_format, image_path
        ),
        name,
        fail_ok,
    )
    return json.loads(output)


def image_delete(client, image_ident, fail_ok=False):
    return client.image("delete", "", image_ident, fail_ok)


def image_set(client, image_ident, param, fail_ok=False):
    return client.image("set", param, image_ident, fail_ok)


def image_show(client, image_ident, fail_ok=False):
    output = client.image("show", "-f json", image_ident, fail_ok)
    return json.loads(output)


def image_add_project(client, image_ident, project, fail_ok=False):
    return client.image(
        "add project", "", "{0} {1}".format(image_ident, project), fail_ok
    )


def image_remove_project(client, image_ident, project, fail_ok=False):
    return client.image(
        "remove project", "", "{0} {1}".format(image_ident, project), fail_ok
    )


def network_create(client, shared="no-share", name=None, fail_ok=False):
    if not name:
        name = data_utils.rand_name("network")
    output = client.network("create", "--{0} -f json".format(shared), name, fail_ok)
    return json.loads(output)


def network_delete(client, network_ident, fail_ok=False):
    return client.network("delete", "", network_ident, fail_ok)


def network_show(client, network_ident, fail_ok=False):
    output = client.network("show", "-f json", network_ident, fail_ok)
    return json.loads(output)


def network_rbac_create(
    client,
    project,
    network_ident,
    action="access_as_shared",
    share_type="network",
    fail_ok=False,
):
    output = client.network(
        "rbac create",
        "--action {0} --type {1} --target-project {2} -f json".format(
            action, share_type, project
        ),
        network_ident,
        fail_ok,
    )
    return json.loads(output)


def network_rbac_delete(client, network_rbac_ident, fail_ok=False):
    return client.network("rbac delete", "", network_rbac_ident, fail_ok)


def node_console_enable(client, node_ident, fail_ok=False):
    return client.baremetal("node console enable", "", node_ident, fail_ok)


def node_console_disable(client, node_ident, fail_ok=False):
    return client.baremetal("node console disable", "", node_ident, fail_ok)


def node_console_show(client, node_ident, fail_ok=False):
    output = client.baremetal("node console show", "-f json", node_ident, fail_ok)
    return json.loads(output)


def node_create(client, driver="fake-hardware", name=None, fail_ok=False, **kwargs):
    if not name:
        name = data_utils.rand_name("baremetal-node")

    kwargs["name"] = name
    kwargs["driver"] = driver

    valid_flags = (
        "driver",
        "name",
    )

    flags = kwargs_to_flags(valid_flags, kwargs)
    flags += " -f json"

    output = client.baremetal("node create", flags, "", fail_ok)
    return json.loads(output)


def node_delete(client, node_ident, fail_ok=False):
    return client.baremetal("node delete", "", node_ident, fail_ok)


def node_power_on(client, node_ident, fail_ok=False):
    return client.baremetal("node power on", "", node_ident, fail_ok)


def node_power_off(client, node_ident, fail_ok=False):
    return client.baremetal("node power off", "", node_ident, fail_ok)


def node_set(client, node_ident, param, value=None, fail_ok=False):
    if value is None:
        return client.baremetal(
            "node unset", "--{0}".format(param), node_ident, fail_ok
        )
    return client.baremetal(
        "node set", "--{0} {1}".format(param, value), node_ident, fail_ok
    )


def node_set_provision_state(client, node_ident, provision_state, fail_ok=False):
    client.baremetal("node {0}".format(provision_state), "", node_ident, fail_ok)
    # wait until target provision state is None
    node = node_show(client, node_ident, fail_ok)
    while node["target_provision_state"] is not None:
        node = node_show(client, node_ident, fail_ok)
        time.sleep(15)


def node_show(client, node_ident, fail_ok=False):
    output = client.baremetal("node show", "-f json", node_ident, fail_ok)
    return json.loads(output)


def port_create(client, network_ident, name=None, fail_ok=False):
    if not name:
        name = data_utils.rand_name("port")
    output = client.port(
        "create", "--network {0} -f json".format(network_ident), name, fail_ok
    )
    return json.loads(output)


def port_delete(client, port_ident, fail_ok=False):
    return client.port("delete", "", port_ident, fail_ok)


def quota_set(client, params, project_id, fail_ok=False):
    client.quota("set", params, project_id, fail_ok)


def quota_show(client, project_id, fail_ok=False):
    output = client.quota("show", "-f json", project_id, fail_ok)
    return json.loads(output)


def volume_create(client, name=None, size=1, fail_ok=False):
    if not name:
        name = data_utils.rand_name("volume")

    output = client.volume("create", "--size {0} -f json".format(size), name, fail_ok)
    return json.loads(output)


def volume_delete(client, volume_ident, fail_ok=False):
    return client.volume("delete", "", volume_ident, fail_ok)


def volume_show(client, volume_ident, fail_ok=False):
    output = client.volume("show", "-f json", volume_ident, fail_ok)
    return json.loads(output)


def volume_transfer_request_accept(client, request_id, auth_key, fail_ok=False):
    output = client.volume(
        "transfer request accept",
        "--auth-key {0} -f json".format(auth_key),
        request_id,
        fail_ok,
    )
    return json.loads(output)


def volume_transfer_request_create(client, volume_ident, fail_ok=False):
    output = client.volume("transfer request create", "-f json", volume_ident, fail_ok)
    return json.loads(output)


def volume_transfer_request_create_and_accept(
    from_client, to_client, volume_ident, fail_ok=False
):
    transfer_request = volume_transfer_request_create(
        from_client, volume_ident, fail_ok
    )
    transfer_accept = volume_transfer_request_accept(
        to_client, transfer_request["id"], transfer_request["auth_key"], fail_ok
    )
    return transfer_accept


def metalsmith_deploy(client, image_ident, network_ident, fail_ok=False):
    return client.metalsmith(
        "deploy",
        "",
        "--image {0} --network {1} --resource-class {2}".format(
            image_ident, network_ident, "baremetal"
        ),
        fail_ok,
    )

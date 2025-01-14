# python-esiclient

`python-esiclient` extends the OpenStack CLI to provide simplified user workflows, encapsulating multiple OpenStack CLI commands into a single CLI command.

To install as a package:
 - `pip install python-esiclient`

To install from source:
 - clone this repository
 - install all requirements: `pip install -r requirements.txt`
 - install: `python setup.py install`

## `openstack esi node network <command>`

These commands manage network connections to nodes.

### `openstack esi node network list`

List node/network attachments.

```
openstack esi node network list
   [--node <node>]
   [--network <network>]
```

- `--node <node>`: Filter by node (name or UUID)
- `--network <network>`:  Filter by network (name or UUID)

### `openstack esi node network attach`

Attach network to a node.

```
openstack esi node network attach
   (--network <network> | --port <port> | --trunk <trunk>)
   [--mac-address <mac-address>]
   <node>
```

- `--network <network>`:  Network (name or UUID)
- `--port <port>`:  Neutron port (name or UUID)
- `--trunk <trunk>`:  Neutron trunk (name or UUID)
- `--mac-address <mac-address>`:  Node MAC address to attach the network to.
- `node`: Node (name or UUID)

### `openstack esi node network detach`

Detach network from a node.

```
openstack esi node network detach
   [--port <port>]
   <node>
```

- `--port <port>`:  Port (name or UUID)
- `node`: Node (name or UUID)

## `openstack esi trunk <command>`

These commands manage trunk ports.

### `openstack esi trunk list`

List trunk ports.

```
openstack esi trunk list
```

### `openstack esi trunk create`

Create a trunk port.

```
openstack esi trunk create
   [--native-network <native-network>]
   [--tagged-networks <tagged-network>]
   <name>
```

- `--native-network <native-network>`: Native network (name or UUID)
- `--tagged-networks <tagged-network>`:  Tagged network (name or UUID); can specify multiple
- `name`: Name of the trunk port

### `openstack esi trunk add network`

Add a network to a trunk port.

```
openstack esi trunk add network
   [--tagged-networks <tagged-network>]
   <name>
```

- `--tagged-networks <tagged-network>`:  Tagged network (name or UUID); can specify multiple
- `name`: Name of the trunk port

### `openstack esi trunk remove network`

Remove a network from a trunk port.

```
openstack esi trunk remove network
   [--tagged-networks <tagged-network>]
   <name>
```

- `--tagged-networks <tagged-network>`:  Tagged network (name or UUID); can specify multiple
- `name`: Name of the trunk port

### `openstack esi trunk delete`

Delete a trunk port.

```
openstack esi trunk delete
   <name>
```

- `name`: Name of the trunk port

### `openstack esi node volume attach`

Boot a node with a volume

```
openstack esi node volume attach
   (--network <network> | --port <port>)
   [--mac-address <mac-address>]
   <node> <volume>
```

- `--network <network>`:  Network (name or UUID)
- `--port <port>`:  Neutron port (name or UUID)
- `node`: Node (name or UUID)
- `volume`: Volume (name or UUID)

## `openstack esi switch <command>`

These commands allow you to treat ESI as a switch.

### `openstack esi switch vlan list`

List VLANs and associated switch ports on a switch.

```
openstack esi switch vlan list <switch>
```

- `switch`: Switch

### `openstack esi switch port list`

List switch ports and associated VLANs on a switch.

```
openstack esi switch port list <switch>
```

- `switch`: Switch

### `openstack esi switch port enable access`

Attach VLAN to a switchport on a switch.

```
openstack esi switch port enable access
   <switch>
   <switchport>
   <vlan>
```

- `switch`: Switch
- `switchport`: Switchport
- `vlan`: VLAN

### `openstack esi switch port disable access`

Disable VLAN access to a switchport on a switch.

```
openstack esi switch port disable access
   <switch>
   <switchport>
```

- `switch`: Switch
- `switchport`: Switchport

### `openstack esi switch port enable trunk`

Attach VLAN to a switchport as the native VLAN of a trunk on a switch.

```
openstack esi switch port enable trunk
   <switch>
   <switchport>
   <vlan>
```

- `switch`: Switch
- `switchport`: Switchport
- `vlan`: VLAN

### `openstack esi switch port disable trunk`

Disable trunk on a switchport on a switch.

```
openstack esi switch port disable trunk
   <switch>
   <switchport>
```

- `switch`: Switch
- `switchport`: Switchport

### `openstack esi switch trunk add vlan`

Add VLAN to a trunk on a switchport.

```
openstack esi switch trunk add vlan
   <switch>
   <switchport>
   <vlan>
```

- `switch`: Switch
- `switchport`: Switchport
- `vlan`: VLAN

### `openstack esi switch trunk remove vlan`

Remove VLAN from a trunk on a switchport.

```
openstack esi switch trunk remove vlan
   <switch>
   <switchport>
   <vlan>
```

- `switch`: Switch
- `switchport`: Switchport
- `vlan`: VLAN

## `openstack esi cluster <command>`

These commands orchestrate and undeploy simple bare metal clusters.

### `openstack esi cluster orchestrate`

Orchestrate a simple cluster.

```
openstack esi cluster orchestrate <config-file>
```

- `<config file>`: Configuration file; for example

```
{
    "node_configs": [
	{
	    "nodes": {
		"node_uuids": ["node1"]
	    },
	    "network": {
		"network_uuid": "private-network-1",
		"tagged_network_uuids": ["private-network-2"],
		"fip_network_uuid": "external"
	    },
	    "provisioning": {
		"provisioning_type": "image",
		"image_uuid": "image-name",
		"ssh_key": "/path/to/ssh/key"
	    }
	},
	{
	    "nodes": {
		"num_nodes": "2",
		"resource_class": "baremetal"
	    },
	    "network": {
		"network_uuid": "private-network-1"
	    },
	    "provisioning": {
		"provisioning_type": "image_url",
		"url": "http://url.for/image",
	    }
	}
    ]
}
```

### `openstack esi cluster list`

List clusters deployed through ESI, along with their associated resources.

```
openstack esi cluster list
```

### `openstack esi cluster undeploy`

Undeploy a cluster deployed through ESI.

```
openstack esi cluster undeploy <cluster-uuid>
```

- `<cluster uuid>`: Cluster UUID; can be found by running `openstack esi cluster list`

## `openstack esi openshift <command>`

These commands orchestrate and undeploy OpenShift clusters.

### `openstack esi openshift orchestrate`

Orchestrate an OpenShift cluster.

```
openstack esi openshift orchestrate <config-file>
```

- `<config file>`: Configuration file; for example

```
{
    "cluster_name": "my-cluster",
    "openshift_version": "4.13.12",
    "high_availability_mode": "Full",
    "base_dns_domain": "my.domain",
    "api_vip": "192.168.1.250",
    "ingress_vip": "192.168.1.249",
    "ssh_public_key": "my-public-key",
    "external_network_name": "external",
    "private_network_name": "my-private-network",
    "private_subnet_name": "my-private-subnet",
    "nodes": ["node1", "node2", "node3"]
}
```

### `openstack esi openshift undeploy`

Undeploy an OpenShift cluster orchestrated through ESI.

```
openstack esi openshift undeploy <config-file>
```

- `<config file>`: Configuration file used to orchestrate OpenShift cluster

# CLI commands documentation

## Node/Network

Links to the commands are here:
* [Attach](#attach)
* [Detach](#detach)
* [List](#list)

Each of these functions has a parser containing data.

### <a name="attach"></a>Attach

The attach command will attack a network to a node.

* `openstack esi node network attach <node> --port <port> --network <network>`
    * Exactly one port or network is needed.
    * node: name or UUID of the node.
    * port: name or UUID of the port.
    * network: name or UUID of the network.
* Returns the node, port address, fixed IP, IP address and which network was attached to the node.

### <a name="detach"></a>Detach

The detach command will detach a network from a node.

* `openstack esi node network detach <node> <port>`
    * node: name or UUID of the node.
    * port: name or UUID of the port.

### <a name="list"></a>List

The list command will list the networks that are attached to a node.

* `openstack esi node network list --node <node> --network <network>`
    * node: name or UUID of the node.
    * network: name or UUID of the network.
* The parameters of the command filter the output.
* Returns a list of nodses and attached networks.

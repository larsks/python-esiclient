# CLI commands documentation

## Node networking

### node network attach

Attach network to node

```
openstack esi node network attach [-h]
                                  [-f {json,shell,table,value,yaml}]
                                  [-c COLUMN] [--noindent]
                                  [--prefix PREFIX]
                                  [--max-width <integer>] [--fit-width]
                                  [--print-empty] [--network <network>]
                                  [--port <port>] [--trunk <trunk>]
                                  [--mac-address <mac address>]
                                  <node>

```

### node network detach

Detach network from node

```
openstack esi node network detach [-h] [--port <port>] <node>
```

### node network list

List networks attached to node

```
openstack esi node network list [-h] [-f {csv,json,table,value,yaml}]
                                [-c COLUMN]
                                [--quote {all,minimal,none,nonnumeric}]
                                [--noindent] [--max-width <integer>]
                                [--fit-width] [--print-empty]
                                [--sort-column SORT_COLUMN]
                                [--sort-ascending | --sort-descending]
                                [--node <node>] [--network <network>]
                                [--long]
```

## Port forwarding

Create a port forward from a floating ip to an internal address.

### port forwarding create

```
openstack esi port forwarding create [-h]
                                     [-f {csv,json,table,value,yaml}]
                                     [-c COLUMN]
                                     [--quote {all,minimal,none,nonnumeric}]
                                     [--noindent]
                                     [--max-width <integer>]
                                     [--fit-width] [--print-empty]
                                     [--sort-column SORT_COLUMN]
                                     [--sort-ascending | --sort-descending]
                                     [--description DESCRIPTION]
                                     [--internal-ip-network INTERNAL_IP_NETWORK]
                                     [--internal-ip-subnet INTERNAL_IP_SUBNET]
                                     [--port PORT]
                                     internal_ip_descriptor
                                     external_ip_descriptor
```

### port forwarding delete

Delete a port forward from a floating ip to an internal address.

```
openstack esi port forwarding delete [-h]
                                     [-f {csv,json,table,value,yaml}]
                                     [-c COLUMN]
                                     [--quote {all,minimal,none,nonnumeric}]
                                     [--noindent]
                                     [--max-width <integer>]
                                     [--fit-width] [--print-empty]
                                     [--sort-column SORT_COLUMN]
                                     [--sort-ascending | --sort-descending]
                                     [--port PORT]
                                     internal_ip_descriptor
                                     external_ip_descriptor
```

### port forwarding purge

Purge all port forwards associated with a floating ip address.

```
openstack esi port forwarding purge [-h]
                                    [-f {csv,json,table,value,yaml}]
                                    [-c COLUMN]
                                    [--quote {all,minimal,none,nonnumeric}]
                                    [--noindent]
                                    [--max-width <integer>]
                                    [--fit-width] [--print-empty]
                                    [--sort-column SORT_COLUMN]
                                    [--sort-ascending | --sort-descending]
                                    [floating_ips ...]
```

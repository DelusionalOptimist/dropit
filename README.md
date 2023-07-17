# dropit

dropit is a packet filter (or a firewall if you're that old :P).
It uses XDP to intercept network traffic, before it enters the OS network stack and filters it based on user defined rules. Rules are a combination of network layer and transport layer headers.
Right now only incoming packets are monitored.

## Usage
* To build and run in a container such that it monitors the container's network interface, run:
  ```
  make docker-run
  ```
* To monitor your host's network interface, use:
  ```
  make docker-run-host
  ```

If run successfully, you'll see a table printed with packet data and status.
NOTE: So far only linux kernel 5.15+ has been tested

### CLI Arguments
```
$ dropit -h
Usage of dropit:
      --config string      Absolute path to optional config file containing filter rules (default "/opt/dropit/dropit.yaml")
      --interface string   Network interface to monitor (default "eth0")
```

### Filtering
A reference filter file is included in [sample](./sample/dropit.yaml) directory. It blocks access to port `8080` from all sources.
For testing, an http server listening on `8080` in the dropit container, is bound to host port `8080`. You can test by sending requests to it.

It is also possible to add, update and delete filter rules at runtime by editing the config file, dropit uses fs notifications to watch for changes.

Each rule consists of:
```
id: <string> (UTF-8 string)
sourceIP: <string> (single IPV4 address OR * to match any address)
destinationPort: <int|string> (single packet destination port OR * to match any port)
sourcePort: <int|string> (single packet source port OR * to match any port)
protocol: <string> (TCP | UDP | * to match any protocols)
```
**All the above fields are required.**

## TODOs
* list of IPs, CIDR, (maybe domain names?)
* list, range of ports
* actions - allow/block
* direction - ingress/egress (need TC hooks)

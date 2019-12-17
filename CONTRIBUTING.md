# Contributing Guide

## Pull Request Guidelines

* Split the commits in features to be added.
* Each commit has to be buildable.
* Follow the coding style on linux kernel (https://www.kernel.org/doc/html/v4.10/process/coding-style.html).
* **DO NOT** push branch with a merge commit, **ALWAYS** use fetch/rebase.
* Run the daemon with the tool valgrind (https://valgrind.org/) to avoid.
* Try to send a test script on the commit so the reviewers/maintainers can test it.

## Developement Setup

You can use the docket environment but can also decide to install the service locally

Start the knot daemon:

`$ sudo src/knotd -nr -c src/knotd.conf`

Start the proxy from tcp IPV4/IPV6 to unix sockets:

`$ inetbr/inetbrd -n`

Start the mock connector service to comunicate with cloud:

`$ test/mock-connector listen`

Start the device mock script:

`$ test/test-conn --debug`

## Project Structure

* `test`: contains scripts for tests. The tests are written in python.
* `doc`: contains the DBus documentation.
* inetbr: contains the source code of inetbrd, a daemon that translate IPV4/IPV6 sockets in unix socket to be consumed by knot daemon aka knotd.
* `docker`: contains files used for the docker container.
* `json`: contains JSON files with examples of messages formated when sent/received from cloud.
* `hooks`: contains scripts hooks to be running with git commands.
* `tools`: contains the source code of ktool, a tool that send the KNoT message in to a unix socket that knotd is listennig.
* `src`: contains the source code of knotd, the KNoT daemon that translate the knot protocol to JSON KNoT protocol.
  - `knotd.conf`: contains configuration about credentials to send messages to cloud.
  - `knot.conf`: file to have access to system bus in Dbus
  - `main.c`: contains code with the main loop and is responsible to bootstrap/call the other files.
  - `settings.c`: contains code associated to command line options.
  - `storage.c`: contains code associated to read/write the content of `knotd.conf` file.
  - `manager.c`: contains code to start the DBus service, bringing the interface settings to configure credentials and also to start the message translation module.
  - `dbus.c`: contains code that communicate to dbus-daemon which verify if the daemon can access the system bus.
  - `msg.c`: contains code related to receiving and sending message,message translation from a device to a cloud.
  - `proxy.c`: contains code related to dbus proxy daemon aka nrfd, daemon that abstract nrf24 radio connection.
  - `device.c`: contains code related to DBus interface Device.
  - `node.c`: contains code related to connection with the device, it opens an unix socket server.
  - `parser.c`: contains code related to serialization and parsing to/from JSON.
  - `mq.c`: contains code related to operations in RabbitMQ with libell (embedded linux library).
  - `cloud.c`: contains code related to the API for communicating with connector. It uses the source code `mq.c` to abstract that it is communicating with rabbitmq. It uses source code `parser.c` to abstract the JSON message format.
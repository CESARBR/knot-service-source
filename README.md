# KNOT Service for Linux systems

KNOT service is part of KNOT project. It aims to provide a "proxy" service
for KNOT nodes, allowing power constrained embedded device to interact
with cloud services.

The initial target platform are nRF24L01 nodes, and Raspiberry PI GW. nRF24L01
is a highly integrated, ultra low power (ULP) 2Mbps RF transceiver IC for the
2.4GHz ISM band. On a second project phase, other radio access technologies
such as Bluetooth Low Energy, and Wi-Fi are planned.

Dependencies:
- knot-protocol-source
- knot-hal-source
- ell >= 1.7
- json-c v0.13.1
- rabbitmq-c
- automake
- libtool
- libssl-dev
- valgrind (optional)

## How to install dependencies:

`$ sudo apt-get install automake libtool libssl-dev valgrind`

### Install libell
To install libell, you have to clone the below repository and follow the instructions to install it:

git://git.kernel.org/pub/scm/libs/ell/ell.git

### Install json-c

To install the version 0.13.1 of json-c, you have to clone the repository and follow the instructions:
https://github.com/json-c/json-c/releases/tag/json-c-0.13.1-20180305

### Install rabbitmq-c

After install cmake, install rabbitmq-c. You have to clone the repository and follow the instructions:
https://github.com/alanxz/rabbitmq-c

## How to build:
You have to install the knot-protocol-source and the knot-hal-source, so you can run:

`$./bootstrap-configure && make`

### How to check for memory leaks and open file descriptors:
```shell
$ valgrind --leak-check=full --track-fds=yes ./src/knotd -nr -c src/knotd.conf
```

### How to test locally:

Start the knot daemon:

`$ sudo src/knotd -nr -c src/knotd.conf`

Start the proxy from tcp IPV4/IPV6 to unix sockets:

`$ inetbr/inetbrd -n`

Start the mock connector service to comunicate with cloud:

`$ test/mock-connector listen`

Start the device mock script:

`$ test/test-conn --debug`

## How to test knot protocol messages

`$ tools/ktool [options]`

### Application Options:
```shell
        -a, --add                               Register a device to Meshblu. Eg: ./ktool --add [-U=value | T=value| I=value]
        -s, --schema                            Get/Put JSON representing device's schema. Eg: ./ktool --schema -u=value -t=value -j=value [-U=value | T=value]
        -C, --config                            Listen for config file. Eg: ./ktool --config -u=value -t=value [-U=value | -T=value]
        -c, --connect                           Comprehensive of add, schema and config. If uuid and token are given, authenticates it. Otherwise, register a new device. Eg: ./ktool --connect -j=value [-u=value | -t=value |-U=value | -T=value]
        -r, --remove                            Unregister a device from Meshblu. Eg: ./ktool --remove -u=value -t=value [-U=value | T=value]
        -d, --data                              Sends data of a given device. Eg: ./ktool --data -u=value -t=value -j=value [-U=value | -T=value]
        -i, --id                                Identify (Authenticate) a Meshblu device.
        -S, --subscribe                         Subscribe for messages of a given device.
        -n, --unsubscribe                       Unsubscribe for messages.
```
### Options usage:
```shell
        -I, --device-id                         Device's ID.
        -u, --uuid                              Device's UUID.
        -t, --token                             Device's token.
        -j, --json                              Path to JSON file.
        -U, --unix                              Specify unix socket to connect. Default: knot.
        -T, --tty                               Specify TTY to connect.
        -h  --help                              Show help options
```
## How to run 'knotd' specifying host & port:

`$ sudo src/knotd -nr -c src/knotd.conf --rabbitmq-url amqp://user:password@serverdomain:5672/vhost`

## How to test a device connection:

The command bellow will register a device which sends a lamp status, and the
credentials in the path `./thing_credentials.json`:

`$ test/test-conn.py -f ./thing_credentials.json`

Note: If you run the same command again it will authenticate with knotd.

It's possible use options to change what the device can send as with the bellow command:

`$ test/test-conn.py -d json/data-array.json -s json/schema-array.json`

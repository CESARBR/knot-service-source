#!/usr/bin/python3
#
#  This file is part of the KNOT Project
#
#  Copyright (c) 2019, CESAR. All rights reserved.
#
#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import pika
import logging
import json
import argparse
import secrets

cloud_exchange = 'cloud'
fog_exchange = 'fog'

QUEUE_CLOUD_NAME = 'cloud-messages'

EVENT_REGISTER = 'device.register'
KEY_REGISTERED = 'device.registered'

EVENT_UNREGISTER = 'device.unregister'
KEY_UNREGISTERED = 'device.unregistered'

EVENT_LIST = 'device.cmd.list'
KEY_LIST_DEVICES = 'device.list'

EVENT_SCHEMA = 'schema.update'
KEY_SCHEMA = 'schema.updated'

EVENT_DATA = 'data.publish'

KEY_UPDATE = 'data.update'
KEY_REQUEST = 'data.request'

logging.basicConfig(
    format='%(asctime)s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

def __parse_update_message(msg_file):
    if msg_file:
        with open(msg_file) as fd:
            msg = json.load(fd)
    else:
        msg = {
            "id": "0123456789abcdef",
            "data": [{"sensor_id": 253, "value": True}]
        }
    return json.dumps(msg)

def __parse_request_message(msg_file):
    if msg_file:
        with open(msg_file) as fd:
            msg = json.load(fd)
    else:
        msg = {
            "id": "0123456789abcdef",
            "data": [253]
        }
    return json.dumps(msg)

def __on_msg_received(channel, method, properties, body):
    logging.info("%r:%r" % (method.routing_key, body))

    if method.routing_key == EVENT_REGISTER:
        message = json.loads(body)
        message['token'] = secrets.token_hex(20)
        del message['name']
        channel.basic_publish(exchange=fog_exchange,
                              routing_key=KEY_REGISTERED, body=json.dumps(message))
    elif method.routing_key == EVENT_UNREGISTER:
        message = body
        channel.basic_publish(exchange=fog_exchange,
                              routing_key=KEY_UNREGISTERED, body=message)
    elif method.routing_key == EVENT_LIST:
        message = [
        {
            'id': secrets.token_hex(8),
            'name': 'test',
            'schema': [{
                "sensor_id": 0,
                "value_type": 3,
                "unit": 0,
                "type_id": 65521,
                "name": "LED"
            }]
        },{
            'id': secrets.token_hex(8),
            'name': 'test2',
            'schema': [{
                "sensor_id": 0,
                "value_type": 3,
                "unit": 0,
                "type_id": 65521,
                "name": "LED"
            }]
        }]
        channel.basic_publish(exchange=fog_exchange,
                              routing_key=KEY_LIST_DEVICES, body=json.dumps(message))
    elif method.routing_key == EVENT_SCHEMA:
        message = json.loads(body)
        del message['schema']
        message['error'] = None
        channel.basic_publish(exchange=fog_exchange,
                              routing_key=KEY_SCHEMA, body=json.dumps(message))
    elif method.routing_key == EVENT_DATA:
        return None

    logging.info(" [x] Sent %r" % (message))

def __amqp_start():
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()

    channel.exchange_declare(exchange=fog_exchange, durable=True,
    exchange_type='topic')
    channel.exchange_declare(exchange=cloud_exchange, durable=True,
    exchange_type='topic')

    return channel

# Parser sub-commands
def msg_consume(args):
    channel = __amqp_start()
    result = channel.queue_declare(QUEUE_CLOUD_NAME, exclusive=False, durable=True)
    queue_name = result.method.queue

    channel.queue_bind(
            exchange=cloud_exchange, queue=queue_name, routing_key='device.*')
    channel.queue_bind(
        exchange=cloud_exchange, queue=queue_name, routing_key='device.cmd.list')
    channel.queue_bind(
            exchange=cloud_exchange, queue=queue_name, routing_key='schema.*')
    channel.queue_bind(
            exchange=cloud_exchange, queue=queue_name, routing_key='data.*')
    channel.basic_consume(
    queue=queue_name, on_message_callback=__on_msg_received, auto_ack=True)

    logging.info('Listening to messages')
    channel.start_consuming()

def msg_update(args):
    channel = __amqp_start()
    msg = __parse_update_message(args.json_msg_file)
    channel.basic_publish(exchange=fog_exchange,
                          routing_key=KEY_UPDATE, body=msg)

def msg_request(args):
    channel = __amqp_start()
    msg = __parse_request_message(args.json_msg_file)
    channel.basic_publish(exchange=fog_exchange,
                          routing_key=KEY_REQUEST, body=msg)

def no_command(args):
    parser.print_help()
    exit(1)

parser = argparse.ArgumentParser(description='Mock KNoT Fog Connector')
parser.set_defaults(func=no_command)
subparsers = parser.add_subparsers(help='sub-command help', dest='subcommand')

parser_listen = subparsers.add_parser('listen', help='Listen to messages \
    from client KNoT daemon', formatter_class=argparse.RawTextHelpFormatter)
parser_listen.set_defaults(func=msg_consume)

parser_update = subparsers.add_parser('send-update', help='Sends a message to \
    update the sensor in device', formatter_class=argparse.RawTextHelpFormatter)
parser_update.add_argument('-f', '--json-msg-file', type=str,
    help='''JSON File with update message to be sent.
    Format: {
              "id": <device_id>,
              "data": [{
                  "sensor_id": <sensor_id>,
                  "data": <sensor_data>
              }, ...]
            }
    ''',
    default='', metavar="MSG_FILE")
parser_update.set_defaults(func=msg_update)

parser_request = subparsers.add_parser('send-request', help='Sends a message \
    requesting data from sensor device',
    formatter_class=argparse.RawTextHelpFormatter)
parser_request.add_argument('-f', '--json-msg-file', type=str,
    help='''JSON File with request message to be sent.
    Format: {
              "id": <device_id>,
              "data":[<sensor_id>, ...]
            }
    ''',
    default='', metavar="MSG_FILE")
parser_request.set_defaults(func=msg_request)

options = parser.parse_args()
options.func(options)

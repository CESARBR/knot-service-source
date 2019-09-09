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

logging.basicConfig(
    format='%(asctime)s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='localhost'))
channel = connection.channel()

cloud_exchange = 'cloud'
fog_exchange = 'fog'

EVENT_UNREGISTER = 'device.unregister'
KEY_UNREGISTERED = 'device.unregistered'

EVENT_DATA = 'data.publish'

channel.exchange_declare(exchange=fog_exchange, durable=True,
exchange_type='topic')
channel.exchange_declare(exchange=cloud_exchange, durable=True,
exchange_type='topic')

result = channel.queue_declare('', exclusive=True)
queue_name = result.method.queue

channel.queue_bind(
        exchange=cloud_exchange, queue=queue_name, routing_key='device.*')
channel.queue_bind(
        exchange=cloud_exchange, queue=queue_name, routing_key='data.*')

def callback(ch, method, properties, body):
    logging.info("%r:%r" % (method.routing_key, body))

    if method.routing_key == EVENT_UNREGISTER:
        message = body
        channel.basic_publish(exchange=fog_exchange,
                              routing_key=KEY_UNREGISTERED, body=message)
    elif method.routing_key == EVENT_DATA:
        return None

    logging.info(" [x] Sent %r" % (message))

channel.basic_consume(
    queue=queue_name, on_message_callback=callback, auto_ack=True)

logging.info('Listening to messages')
channel.start_consuming()

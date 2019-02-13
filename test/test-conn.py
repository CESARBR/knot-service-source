#!/usr/bin/python
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

import socket
import struct
import json
import threading
import logging
import sys
import argparse

parser = argparse.ArgumentParser(description='Simulates a thing connection')
parser.add_argument('-f', '--file', dest="filename",
                    help="write credentials to FILE", default="storage.json",
                    type=str, metavar="FILE")
parser.add_argument('-i', '--id', dest="id",
                    help="KNoT id", default=0x0123456789abcdef,
                    type=int, metavar="ID")
parser.add_argument('-n', '--name', dest="name",
                    help="thing name", default='Test',
                    type=str, metavar="NAME")
parser.add_argument('-s', '--schema', dest="schema_file",
                    help="schema file", default='',
                    type=str, metavar="SCHEMA_FILE")
parser.add_argument('-d', '--data', dest="data_file",
                    help="data file", default='',
                    type=str, metavar="DATA_FILE")
parser.add_argument('--debug', action="store_true",
                    help="show debug messages")
options = parser.parse_args()

if options.debug:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
else:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)

THING_ID = options.id
THING_NAME = options.name
HOST = 'localhost'
PORT = 8884
if options.schema_file:
    with open(options.schema_file) as fd:
        schemas = json.load(fd)['schema']
    if options.data_file:
        with open(options.data_file) as fd:
            datas = json.load(fd)['data']
    else:
        raise argparse.ArgumentTypeError('Missing data file')
else:
    schemas = [{
        "sensor_id": 253, "value_type":3,
        "unit":0, "type_id": 65521,
        "name": "Lamp Status"
    }]
    datas = [{
        'sensor_id': 253,
        'value': False
    }]
schemas_sents = []

# Definitions removed by knot-protocol

PROTO_REGISTER_REQ = 0x10
PROTO_REGISTER_RSP = 0x11
PROTO_UNREGISTER_REQ = 0x12
PROTO_UNREGISTER_RSP = 0x13
PROTO_AUTH_REQ = 0x14
PROTO_AUTH_RSP = 0x15

PROTO_PUSH_DATA_REQ = 0x20
PROTO_PUSH_DATA_RSP = 0x21
PROTO_POLL_DATA_REQ = 0x30
PROTO_POLL_DATA_RSP = 0x31

PROTO_SCHM_FRAG_REQ = 0x40
PROTO_SCHM_FRAG_RSP = 0x41
PROTO_SCHM_END_REQ = 0x42
PROTO_SCHM_END_RSP = 0x43

# Format for serialization

HEADER_FMT = 'BB'           # 2 uint8_t, (type, payload_len)
REGISTER_FMT = 'Q64s'       # uint64_t, char[64] (thing_id, name)
REGISTER_RSP_FMT = '37s40s' # char[37], char[40] (uuid, token)
AUTH_FMT = '37s40s'         # char[37], char[40] (uuid, token)
SCHEMA_FMT = 'BBBH22s' # 3 uint8_t, uint16_t, char[22] (sensor_id, value_type, unit, type_id, name)

# Util functions

def to_string(string):
    if not isinstance(string, bytes):
        string = string.encode('utf-8')
    return string

def set_interval(func, time, **kwargs):
    def func_wrapper():
        set_interval(func, time, **kwargs)
        func(**kwargs)
    t = threading.Timer(time, func_wrapper)
    t.daemon = True
    t.start()
    return t

def get_format_type(value):
    if isinstance(value, int):
        return 'i'
    elif isinstance(value, float):
        return 'f'
    elif isinstance(value, bool):
        return '?'
    return '16s'

def knot_proto_to_str(msg_type):
    return {
        0x10: 'REGISTER_REQUEST',
        0x11: 'REGISTER_RESPONSE',
        0x12: 'UNREGISTER_REQUEST',
        0x13: 'UNREGISTER_RESPONSE',
        0x14: 'AUTHENTICATE_REQUEST',
        0x15: 'AUTHENTICATE_RESPONSE',
        0x20: 'PUSH_DATA_REQUEST',
        0x21: 'PUSH_DATA_RESPONSE',
        0x30: 'POLL_DATA_REQUEST',
        0x31: 'POLL_DATA_RESPONSE',
        0x40: 'SCHEMA_FRAG_REQUEST',
        0x41: 'SCHEMA_FRAG_RESPONSE',
        0x42: 'SCHEMA_END_REQUEST',
        0x43: 'SCHEMA_END_RESPONSE'
    }.get(msg_type)

# Functions to send knot protocol messages

def send_knot_msg_register(sock, thing_id, name):
    logging.debug('[payload_len: %d] Sending knot_msg 0x%x (%s)', struct.calcsize(REGISTER_FMT),
                  PROTO_REGISTER_REQ, knot_proto_to_str(PROTO_REGISTER_REQ))
    header = struct.pack(HEADER_FMT, PROTO_REGISTER_REQ, struct.calcsize(REGISTER_FMT))
    msg = header + struct.pack('Q', thing_id) + struct.pack('64s', to_string(name))
    return sock.send(msg)

def send_knot_msg_auth(sock, uuid, token):
    logging.debug('[payload_len: %d] Sending knot_msg 0x%x (%s)', struct.calcsize(AUTH_FMT),
                  PROTO_AUTH_REQ, knot_proto_to_str(PROTO_AUTH_REQ))
    header = struct.pack(HEADER_FMT, PROTO_AUTH_REQ, struct.calcsize(AUTH_FMT))
    msg = header + struct.pack('77s', to_string(uuid + token))
    return sock.send(msg)

def send_knot_msg_schema(sock, sensor_id, value_type, unit, type_id, name):
    logging.debug('[payload_len: %d] Sending knot_msg 0x%x (%s)', struct.calcsize(SCHEMA_FMT),
                  PROTO_SCHM_FRAG_REQ, knot_proto_to_str(PROTO_SCHM_FRAG_REQ))
    logging.debug('Schema: %s', json.dumps({'sensor_id': sensor_id, 'value_type': value_type,
                                            'unit': unit, 'type_id': type_id, 'name': name}))
    header = struct.pack(HEADER_FMT, PROTO_SCHM_FRAG_REQ, struct.calcsize(SCHEMA_FMT))
    msg = header + struct.pack('BBB', sensor_id, value_type, unit)
    msg = msg + struct.pack('H', type_id)
    msg = msg + struct.pack('23s', to_string(name))
    return sock.send(msg)

def send_knot_msg_push_data(sock, sensor_id, value):
    logging.info('Sending data: sensor_id %s value %s', sensor_id, str(value))
    payload_len = struct.calcsize('B') + struct.calcsize(get_format_type(value))
    logging.debug('[payload_len:%d] Sending knot_msg 0x%x (%s)', payload_len, PROTO_PUSH_DATA_REQ,
                  knot_proto_to_str(PROTO_PUSH_DATA_REQ))
    header = struct.pack(HEADER_FMT, PROTO_PUSH_DATA_REQ, payload_len)
    msg = header + struct.pack('B', sensor_id)
    msg = msg + struct.pack(get_format_type(value), value)
    return sock.send(msg)

# Functions to handle knot protocol messages received

def handle_register(msg):
    logging.info('Registered')
    _, _, uuid, token = struct.unpack(HEADER_FMT + REGISTER_RSP_FMT, msg)
    credentials = {'uuid': uuid[1:].decode('utf-8'), 'token': token.decode('utf-8')}
    with open(options.filename, 'w') as fd:
        json.dump(credentials, fd)
    send_knot_msg_auth(s, uuid[1:], token)

def handle_auth():
    logging.info('Authenticated')
    try:
        sensor = schemas.pop()
        schemas_sents.append(sensor)
        sensor['sock'] = s
        send_knot_msg_schema(**sensor)
    except IndexError:
        for data in datas:
            interval = data.pop('interval') if 'interval' in data else 10
            data['sock'] = s
            logging.info('Data_item %d will send every %d seconds', data['sensor_id'], interval)
            set_interval(send_knot_msg_push_data, interval, **data)

def handle_schema():
    if schemas:
        sensor = schemas.pop()
        schemas_sents.append(sensor)
        sensor['sock'] = s
        send_knot_msg_schema(**sensor)
        return
    s.send(struct.pack(HEADER_FMT, PROTO_SCHM_END_REQ, 0))

def handle_schema_end():
    logging.info('Schema sent')
    for data in datas:
        interval = data.pop('interval') if 'interval' in data else 10
        data['sock'] = s
        logging.info('Data_item %d will send every %d seconds', data['sensor_id'], interval)
        set_interval(send_knot_msg_push_data, interval, **data)

def get_data(msg):
    _, _, sensor_id = struct.unpack(HEADER_FMT + 'B', msg)
    logging.info('get_data: sensor_id: %s', sensor_id)
    try:
        data = next(i for i in datas if i['sensor_id'] == sensor_id)
        send_knot_msg_push_data(s, sensor_id, data['value'])
    except StopIteration:
        logging.error('No data found for sensor_id: %s', sensor_id)

def set_data(msg):
    _, _, sensor_id = struct.unpack(HEADER_FMT + 'B', msg[0:3])
    try:
        schema = next(sensor for sensor in schemas_sents if sensor['sensor_id'] == sensor_id)
        if schema['value_type'] == 1:
            value = struct.unpack('i', msg[3:])[0]
        elif schema['value_type'] == 2:
            value = round(struct.unpack('f', msg[3:])[0], 2)
        elif schema['value_type'] == 3:
            value = struct.unpack('?', msg[3:])[0]
        elif schema['value_type'] == 4:
            fmt = '%ds' %len(msg[3:])
            value = struct.unpack(fmt, to_string(msg[3:]))[0]

        logging.info('set_data: sensor_id %s value %s', sensor_id, str(value))
        send_knot_msg_push_data(s, sensor_id, value)
        s.send(struct.pack(HEADER_FMT + 'B', PROTO_PUSH_DATA_RSP, 1, sensor_id))
    except StopIteration:
        logging.error('No schema found for sensor_id: %s', sensor_id)

def handle_unregister():
    with open(options.filename, 'w') as fd:
        json.dump({}, fd)
    logging.info('Unregistered')
    s.send(struct.pack(HEADER_FMT, PROTO_UNREGISTER_RSP, 0))
    logging.info('Closing connection')
    s.close()
    exit()

# Main code

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
logging.info('Connection to %s:%d', HOST, PORT)
s.connect((HOST, PORT))

try:
    with open(options.filename) as fd:
        credentials = json.load(fd)
except IOError:
    credentials = {}

if not credentials:
    send_knot_msg_register(s, THING_ID, THING_NAME)
else:
    schemas_sents = schemas
    schemas = []
    nbytes = send_knot_msg_auth(s, str(credentials['uuid']), str(credentials['token']))
    if nbytes < 0:
        logging.debug(nbytes)


while 1:
    msg = s.recv(100)
    msg_type, payload_len = struct.unpack(HEADER_FMT, msg[0:2])
    logging.debug('[payload_len: %d] receive knot_msg = 0x%x (%s)', payload_len,
                  msg_type, knot_proto_to_str(msg_type))
    {
        PROTO_AUTH_RSP: handle_auth,
        PROTO_UNREGISTER_REQ: handle_unregister,
        PROTO_SCHM_FRAG_RSP: handle_schema,
        PROTO_SCHM_END_RSP: handle_schema_end,
        PROTO_REGISTER_RSP: lambda: handle_register(msg),
        PROTO_PUSH_DATA_REQ: lambda: set_data(msg),
        PROTO_PUSH_DATA_RSP: lambda: logging.info('Data sent'),
        PROTO_POLL_DATA_REQ: lambda: get_data(msg),
        PROTO_POLL_DATA_RSP: lambda: logging.info('Data poll'),
    }.get(msg_type)()

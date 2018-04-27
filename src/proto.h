/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2018, CESAR. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

typedef void (*proto_proxy_func_t) (uint64_t device_id, void *user_data);
typedef void (*proto_proxy_ready_func_t) (void *user_data);

typedef struct {
	char *data;
	size_t size;
} json_raw_t;

/* Node operations */
struct proto_ops {
	const char *name;
	unsigned int source_id;
	int (*probe) (const char *host, unsigned int port);
	void (*remove) (void);

	/* Abstraction for connect & close/sign-off */
	int (*connect) (void);
	void (*close) (int sock);

	/* Abstraction for session establishment or registration */
	int (*mknode) (int sock, const char *owner_uuid, json_raw_t *json);
	int (*signin) (int sock, const char *uuid, const char *token,
							json_raw_t *json);
	int (*rmnode)(int sock, const char *uuid, const char *token,
							json_raw_t *jbuf);
	/* Abstraction for device data */
	int (*schema) (int sock, const char *uuid, const char *token,
					const char *jreq, json_raw_t *json);
	int (*data) (int sock, const char *uuid, const char *token,
					const char *jreq, json_raw_t *jbuf);
	int (*fetch) (int sock, const char *uuid, const char *token,
							json_raw_t *json);
	int (*setdata) (int sock, const char *uuid, const char *token,
					const char *jreq, json_raw_t *json);
	/*
	 * Watch that polls or monitors the cloud to check if "CONFIG" changed
	 * or "SET DATA" or "GET DATA".
	 */
	unsigned int (*async) (int sock, const char *uuid, const char *token,
		void (*proto_watch_cb) (json_raw_t, void *), void *user_data,
		void (*proto_watch_destroy_cb) (void *));
	void (*async_stop) (int sock, unsigned int watch_id);
	void (*process) (int sock);
};

int proto_start(const struct settings *settings);
void proto_stop(void);

int proto_connect(void);
void proto_close(int proto_socket);
int proto_mknode(int proto_socket, const char *device_name,
			uint64_t device_id, char *uuid, char *token);
int proto_rmnode(int proto_socket, const char *uuid, const char *token);
int proto_rmnode_by_uuid(const char *uuid);
int proto_signin(int proto_socket, const char *uuid, const char *token,
			struct l_queue **schema, struct l_queue **config);
int proto_schema(int proto_socket, const char *uuid,
		 const char *token, struct l_queue *schema_list);
int proto_data(int proto_socket, const char *uuid,
		      const char *token, uint8_t sensor_id,
		      uint8_t value_type, const knot_data *value);
void proto_getdata(int proto_sock, char *uuid, char *token, uint8_t sensor_id);
void proto_setdata(int proto_sock, char *uuid, char *token, uint8_t sensor_id);

int proto_set_proxy_handlers(int sock,
			     proto_proxy_func_t added,
			     proto_proxy_func_t removed,
			     proto_proxy_ready_func_t ready,
			     void *user_data);

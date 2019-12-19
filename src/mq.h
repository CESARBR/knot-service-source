/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2019, CESAR. All rights reserved.
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

/**
 *  Message Queue header file
 */

typedef bool (*mq_read_cb_t) (const char *exchange,
				   const char *routing_key,
				   const char *body,
				   void *user_data);
typedef void (*mq_connected_cb_t) (void *user_data);

int mq_bind_queue(amqp_bytes_t queue,
			      const char *exchange,
			      const char *routing_key);
amqp_bytes_t mq_declare_new_queue(const char *name);
int mq_set_read_cb(amqp_bytes_t queue, mq_read_cb_t on_read, void *user_data);
int mq_start(struct settings *settings, mq_connected_cb_t connected_cb,
	     void *user_data);
void mq_stop(void);
int8_t mq_publish_persistent_message(amqp_bytes_t queue, const char *exchange,
				const char *routing_keys,
				amqp_table_entry_t *headers,
				size_t num_headers,
				uint64_t expiration,
				const char *body);

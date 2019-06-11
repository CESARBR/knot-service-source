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

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <assert.h>
#include <signal.h>

#include <ell/ell.h>


#include <knot/knot_protocol.h>
#include <knot/knot_types.h>

#include <hal/linux_log.h>

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET			"knot"

/* device name for the register */
#define	KTEST_DEVICE_NAME			"ktest_unit_test"

static uint64_t reg_id = 0x0123456789abcdef;
static int sockfd;
static char uuid128[KNOT_PROTOCOL_UUID_LEN];
static char token[KNOT_PROTOCOL_TOKEN_LEN];
static knot_msg kmsg;
static knot_msg kresp;

static int tcp_connect(void)
{
	struct sockaddr_in addr;
	int err, sock;

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err = errno;
		hal_log_error("tcp socket(): %s (%d)", strerror(err), err);
		return -err;
	}

	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(9994);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		hal_log_error("tcp connect(): %s (%d)", strerror(err), err);
		close(sock);
		return -err;
	}

	return sock;
}

static int tcp6_connect(void)
{
	struct sockaddr_in6 addr;
	int err, sock;

	sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err = errno;
		hal_log_error("tcp6 socket(): %s (%d)", strerror(err), err);
		return -err;
	}

	memset(&addr,0,sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(9996);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		hal_log_error("tcp6 connect(): %s (%d)", strerror(err), err);
		close(sock);
		return -err;
	}

	return sock;
}


static int unix_connect(void)
{
	struct sockaddr_un addr;
	int err, sock;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		err = errno;
		hal_log_error(" >socket failure: %s (%d)", strerror(err), err);
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	strcpy(addr.sun_path + 1, KNOT_UNIX_SOCKET);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		hal_log_error("connect(): %s (%d)", strerror(err), err);
		close(sock);
		return -err;
	}

	return sock;
}

static void unix_connect_test(const void *test_data)
{
	sockfd = unix_connect();
	assert(sockfd > 0);
}

static void unix_close_test(const void *test_data)
{
	assert(close(sockfd) == 0);
	sockfd = -1;
}

static ssize_t do_request(const knot_msg *kmsg, size_t len, knot_msg *kresp)
{
	ssize_t nbytes;
	int err;

	nbytes = write(sockfd, kmsg, len);
	if (nbytes < 0) {
		err = errno;
		hal_log_error("write(): %s(%d)", strerror(err), err);
		return -err;
	}

	nbytes = read(sockfd, kresp, sizeof(knot_msg));
	if (nbytes < 0) {
		err = errno;
		hal_log_error("read(): %s (%d)", strerror(err), err);
		return -err;
	}

	return nbytes;
}

static void authenticate_test(const void *test_data)
{
	ssize_t size;

	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_AUTH_REQ;

	memcpy(kmsg.auth.uuid, uuid128, sizeof(kmsg.auth.uuid));
	memcpy(kmsg.auth.token, token, sizeof(kmsg.auth.token));

	kmsg.hdr.payload_len = sizeof(kmsg.auth) - sizeof(kmsg.hdr);
	size = do_request(&kmsg, sizeof(kmsg.auth), &kresp);

	/* Response consistency */
	assert(size == sizeof(kresp.action));
	assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	assert(kresp.hdr.type == KNOT_MSG_AUTH_RSP);
	assert(kresp.action.result == 0);
}

static void register_missing_devname_test(const void *test_data)
{
	ssize_t size, plen;

	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	/* Sending register message with missing parameters. */

	kmsg.reg.id = ++reg_id;
	kmsg.hdr.payload_len = sizeof(kmsg.reg.id); /* No device name */

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;
	size = do_request(&kmsg, plen, &kresp);

	/* Response consistency */
	assert(size == sizeof(kresp.action));
	assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	assert(kresp.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp.action.result == KNOT_ERR_INVALID);
}

static void register_empty_devname_test(const void *test_data)
{
	ssize_t size, plen;

	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	kmsg.hdr.payload_len = sizeof(kmsg.reg.id) + 1;
	kmsg.reg.id = ++reg_id;

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;
	size = do_request(&kmsg, plen, &kresp);

	/* Response consistency */
	assert(size == sizeof(kresp.action));
	assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	assert(kresp.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp.action.result == KNOT_ERR_INVALID);
}

static void register_valid_devname_test(const void *test_data)
{
	ssize_t size, plen;

	memset(&kresp, 0, sizeof(kresp));
	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	/* Copying name to registration message */
	kmsg.hdr.payload_len = strlen(KTEST_DEVICE_NAME);
	kmsg.reg.id = ++reg_id;
	strcpy(kmsg.reg.devName, KTEST_DEVICE_NAME);

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;
	size = do_request(&kmsg, plen, &kresp);

	/* Response consistency */
	assert(size == sizeof(kresp.cred));

	/* Response opcode & result */
	assert(kresp.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp.action.result == 0);

	printf("UUID: %.36s token:%.40s\n", kresp.cred.uuid, kresp.cred.token);
	memcpy(uuid128, kresp.cred.uuid, sizeof(kresp.cred.uuid));
	memcpy(token, kresp.cred.token, sizeof(kresp.cred.token));
}

static void register_repeated_attempt_test(const void *test_data)
{
	ssize_t size, plen;
	knot_msg kresp2;
	int ret;

	memset(&kresp2, 0, sizeof(kresp2));
	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	/* Copying name to registration message */
	kmsg.hdr.payload_len = strlen(KTEST_DEVICE_NAME);

	/* Do not increment: Use latest registered id  */
	kmsg.reg.id = reg_id;
	strcpy(kmsg.reg.devName, KTEST_DEVICE_NAME);

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;
	size = do_request(&kmsg, plen, &kresp2);

	/* Response consistency */
	assert(size == sizeof(kresp2.cred));

	/* Response opcode & result */
	assert(kresp2.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp2.action.result == 0);
	ret = memcmp(&kresp, &kresp2, size);
	assert(ret == 0);

	printf("UUID: %.36s token:%.40s\n", kresp2.cred.uuid, kresp2.cred.token);
}

static void register_new_id_test(const void *test_data)
{
	ssize_t size, plen;
	knot_msg kresp2;
	int ret;

	/*
	 * Simulates new registration attempt from the
	 * same process using a different id. A new device
	 * (different UUID) must be registered.
	 */
	memset(&kresp2, 0, sizeof(kresp2));
	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	/* Copying name to registration message */
	kmsg.hdr.payload_len = strlen(KTEST_DEVICE_NAME);
	kmsg.reg.id = ++reg_id;
	strcpy(kmsg.reg.devName, KTEST_DEVICE_NAME);

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;
	size = do_request(&kmsg, plen, &kresp2);

	/* Response consistency */
	assert(size == sizeof(kresp2.cred));

	/* Response opcode & result */
	assert(kresp2.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp2.action.result == 0);

	/* Compare with the first received response */
	ret = memcmp(&kresp, &kresp2, size);
	assert(ret != 0);

	printf("UUID: %.36s token:%.40s\n", kresp2.cred.uuid, kresp2.cred.token);
}

static void unregister_valid_device_test(const void *test_data)
{
	memset(&kmsg, 0, sizeof(kmsg));
	memset(&kresp, 0, sizeof(kresp));
	kmsg.hdr.type = KNOT_MSG_UNREG_REQ;

	kmsg.hdr.payload_len = 0;
	assert(do_request(&kmsg, sizeof(kmsg.unreg), &kresp) ==
							sizeof(kresp.action));
	assert(kresp.hdr.payload_len == sizeof(kresp.action.result));
	assert(kresp.hdr.type == KNOT_MSG_UNREG_RSP);
	assert(kresp.action.result == 0);
}

static void tcp_connect_test(const void *test_data)
{
	sockfd = tcp_connect();
	assert(sockfd > 0);
}

static void tcp6_connect_test(const void *test_data)
{
	sockfd = tcp6_connect();
	assert(sockfd > 0);
}

static void tcp_close_test(const void *test_data)
{
	assert(close(sockfd) == 0);
	sockfd = -1;
}

/* Register and run all tests */
int main(int argc, char *argv[])
{

	signal(SIGPIPE, SIG_IGN);

	l_test_init(&argc, &argv);

	l_test_add("/1/unix_connect", unix_connect_test, NULL);
	l_test_add("/1/register_missing_devname",
				register_missing_devname_test, NULL);
	l_test_add("/1/unix_close", unix_close_test, NULL);

	l_test_add("/2/tcp_connect", tcp_connect_test, NULL);
	l_test_add("/2/register_missing_devname",
				register_missing_devname_test, NULL);
	l_test_add("/2/tcp_close", tcp_close_test, NULL);
	l_test_add("/2/tcp_connect6", tcp6_connect_test, NULL);
	l_test_add("/2/register_missing_devname6",
				register_missing_devname_test, NULL);
	l_test_add("/2/tcp_close6", tcp_close_test, NULL);

	l_test_add("/3/unix_connect", unix_connect_test, NULL);
	l_test_add("/3/register_empty_devname",
				register_empty_devname_test, NULL);
	l_test_add("/3/unix_close", unix_close_test, NULL);

	l_test_add("/4/tcp_connect", tcp_connect_test, NULL);
	l_test_add("/4/tcp_register_empty_devname",
				register_empty_devname_test, NULL);
	l_test_add("/4/tcp_close", tcp_close_test, NULL);
	l_test_add("/4/tcp_connect6", tcp6_connect_test, NULL);
	l_test_add("/4/tcp_register_empty_devname6",
				register_empty_devname_test, NULL);
	l_test_add("/4/tcp_close6", tcp_close_test, NULL);

	l_test_add("/5/tcp_connect", tcp_connect_test, NULL);
	l_test_add("/5/tcp_register_empty_devname",
				register_empty_devname_test, NULL);
	l_test_add("/5/tcp_close", tcp_close_test, NULL);
	l_test_add("/5/tcp_connect6", tcp6_connect_test, NULL);
	l_test_add("/5/tcp_register_empty_devname6",
				register_empty_devname_test, NULL);
	l_test_add("/5/tcp_close6", tcp_close_test, NULL);

	l_test_add("/6/unix_connect", unix_connect_test, NULL);
	l_test_add("/6/register_valid_devname",
				register_valid_devname_test, NULL);
	l_test_add("/6/register_repeated_attempt",
				register_repeated_attempt_test, NULL);
	l_test_add("/6/register_new_id",
				register_new_id_test, NULL);
	l_test_add("/6/unix_close", unix_close_test, NULL);

	l_test_add("/7/tcp_connect", unix_connect_test, NULL);
	l_test_add("/7/register_valid_devname",
				register_valid_devname_test, NULL);
	l_test_add("/7/register_repeated_attempt",
				register_repeated_attempt_test, NULL);
	l_test_add("/7/register_new_id",
				register_new_id_test, NULL);
	l_test_add("/7/tcp_close", unix_close_test, NULL);

	l_test_add("/8/unix_connect", unix_connect_test, NULL);
	l_test_add("/8/authenticate",
				authenticate_test, NULL);
	l_test_add("/8/unregister_valid_device",
				unregister_valid_device_test, NULL);
	l_test_add("/8/unix_close", unix_close_test, NULL);

	l_test_add("/9/tcp_connect", unix_connect_test, NULL);
	l_test_add("/9/register_valid_devname",
				register_valid_devname_test, NULL);
	l_test_add("/9/unregister_valid_device",
				unregister_valid_device_test, NULL);
	l_test_add("/9/tcp_close", unix_close_test, NULL);

	return l_test_run();
}

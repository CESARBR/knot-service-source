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
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <signal.h>

#include <ell/ell.h>

#include <knot/knot_protocol.h>
#include <knot/knot_types.h>

/* device name for the register */
#define	KTEST_DEVICE_NAME	"ktest_unit_test"
#define INETBRD_PORT_IPV4 8884
#define INETBRD_PORT_IPV6 8886

static uint64_t reg_id = 0x0123456789abcdef;
static char uuid128[KNOT_PROTOCOL_UUID_LEN];
static char token[KNOT_PROTOCOL_TOKEN_LEN];
static knot_msg kmsg;
static knot_msg kresp;

static ssize_t do_request4(const knot_msg *kmsg, size_t len, knot_msg *kresp)
{
	struct sockaddr_in addr;
	socklen_t addrlen;
	ssize_t recvlen, sentlen;
	int err;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		err = errno;
		fprintf(stderr, "socket(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(INETBRD_PORT_IPV4);

	sentlen = sendto(sockfd, kmsg, len, 0, (struct sockaddr *) &addr,
							sizeof(addr));
	if (sentlen < 0) {
		err = errno;
		fprintf(stderr, "sendto(): %s(%d)\n", strerror(err), err);
		close(sockfd);
		return -err;
	}

	addrlen = sizeof(addr);
	recvlen = recvfrom(sockfd, kresp, sizeof(*kresp), 0,
		       (struct sockaddr *) &addr, &addrlen);
	if (recvlen < 0) {
		err = errno;
		fprintf(stderr, "recvfrom(): %s (%d)", strerror(err), err);
		return -err;
	}

	close(sockfd);

	fprintf(stdout, "Sent: %zu Recv: %zd\n", sentlen, recvlen);

	return recvlen;
}

static ssize_t do_request6(const knot_msg *kmsg, size_t len, knot_msg *kresp)
{
	struct sockaddr_in6 addr;
	socklen_t addrlen;
	ssize_t recvlen, sentlen;
	int err;
	int sockfd;

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		err = errno;
		fprintf(stderr, "socket(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&addr,0,sizeof(addr));
	addr.sin6_family = AF_INET;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(INETBRD_PORT_IPV6);

	sentlen = sendto(sockfd, kmsg, len, 0, (struct sockaddr *) &addr,
							sizeof(addr));
	if (sentlen < 0) {
		err = errno;
		fprintf(stderr, "sendto(): %s(%d)\n", strerror(err), err);
		close(sockfd);
		return -err;
	}

	addrlen = sizeof(addr);
	recvlen = recvfrom(sockfd, kresp, sizeof(*kresp), 0,
		       (struct sockaddr *) &addr, &addrlen);
	if (recvlen < 0) {
		err = errno;
		fprintf(stderr, "recvfrom(): %s (%d)", strerror(err), err);
		return -err;
	}

	close(sockfd);

	fprintf(stdout, "Sent: %zu Recv: %zd\n", sentlen, recvlen);

	return recvlen;
}

static void authenticate_test(const void* user_data)
{
	int ipv6 = L_PTR_TO_INT(user_data);
	ssize_t size;

	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_AUTH_REQ;

	memcpy(kmsg.auth.uuid, uuid128, sizeof(kmsg.auth.uuid));
	memcpy(kmsg.auth.token, token, sizeof(kmsg.auth.token));

	kmsg.hdr.payload_len = sizeof(kmsg.auth) - sizeof(kmsg.hdr);

	if (ipv6)
		size = do_request6(&kmsg, sizeof(kmsg.auth), &kresp);
	else
		size = do_request4(&kmsg, sizeof(kmsg.auth), &kresp);

	/* Response consistency */
	assert(size == sizeof(kresp.action));
	assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	assert(kresp.hdr.type == KNOT_MSG_AUTH_RSP);
	assert(kresp.action.result == 0);
}

static void register_missing_devname_test(const void *user_data)
{
	int ipv6 = L_PTR_TO_INT(user_data);
	ssize_t size, plen;

	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	/* Sending register message with missing parameters. */

	kmsg.reg.id = ++reg_id;
	kmsg.hdr.payload_len = sizeof(kmsg.reg.id); /* No device name */

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;

	if (ipv6)
		size = do_request6(&kmsg, plen, &kresp);
	else
		size = do_request4(&kmsg, plen, &kresp);

	/* Response consistency */
	assert(size == sizeof(kresp.action));
	assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	assert(kresp.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp.action.result == KNOT_ERR_INVALID);
}

static void register_empty_devname_test(const void *user_data)
{
	int ipv6 = L_PTR_TO_INT(user_data);
	ssize_t size, plen;

	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	kmsg.hdr.payload_len = sizeof(kmsg.reg.id) + 1;
	kmsg.reg.id = ++reg_id;

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;

	if (ipv6)
		size = do_request6(&kmsg, plen, &kresp);
	else
		size = do_request4(&kmsg, plen, &kresp);

	/* Response consistency */
	assert(size == sizeof(kresp.action));
	assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	assert(kresp.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp.action.result == KNOT_ERR_INVALID);
}

static void register_valid_devname_test(const void *user_data)
{
	int ipv6 = L_PTR_TO_INT(user_data);
	ssize_t size, plen;

	memset(&kresp, 0, sizeof(kresp));
	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	/* Copying name to registration message */
	kmsg.hdr.payload_len = strlen(KTEST_DEVICE_NAME);
	kmsg.reg.id = ++reg_id;
	strcpy(kmsg.reg.devName, KTEST_DEVICE_NAME);

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;

	if (ipv6)
		size = do_request6(&kmsg, plen, &kresp);
	else
		size = do_request4(&kmsg, plen, &kresp);

	/* Response consistency */
	assert(size == sizeof(kresp.cred));

	/* Response opcode & result */
	assert(kresp.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp.action.result == 0);

	printf("UUID: %.36s token:%.40s\n", kresp.cred.uuid, kresp.cred.token);
	memcpy(uuid128, kresp.cred.uuid, sizeof(kresp.cred.uuid));
	memcpy(token, kresp.cred.token, sizeof(kresp.cred.token));
}

static void register_repeated_attempt_test(const void *user_data)
{
	int ipv6 = L_PTR_TO_INT(user_data);
	ssize_t size, plen;
	knot_msg kresp2;

	memset(&kresp2, 0, sizeof(kresp2));
	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_REG_REQ;

	/* Copying name to registration message */
	kmsg.hdr.payload_len = strlen(KTEST_DEVICE_NAME);

	/* Do not increment: Use latest registered id  */
	kmsg.reg.id = reg_id;
	strcpy(kmsg.reg.devName, KTEST_DEVICE_NAME);

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;

	if (ipv6)
		size = do_request6(&kmsg, plen, &kresp2);
	else
		size = do_request4(&kmsg, plen, &kresp2);

	/* Response consistency */
	assert(size == sizeof(kresp2.cred));

	/* Response opcode & result */
	assert(kresp2.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp2.action.result == 0);
	assert(memcmp(&kresp, &kresp2, size) == 0);

	printf("UUID: %.36s token:%.40s\n",
				kresp2.cred.uuid, kresp2.cred.token);
}

static void register_new_id(const void *user_data)
{
	int ipv6 = L_PTR_TO_INT(user_data);
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

	if (ipv6)
		size = do_request6(&kmsg, plen, &kresp2);
	else
		size = do_request4(&kmsg, plen, &kresp2);

	/* Response consistency */
	assert(size == sizeof(kresp2.cred));

	/* Response opcode & result */
	assert(kresp2.hdr.type == KNOT_MSG_REG_RSP);
	assert(kresp2.action.result == 0);

	/* Compare with the first received response */
	ret = memcmp(&kresp, &kresp2, size);
	assert(ret != 0);

	printf("UUID: %.36s token:%.40s\n",
				kresp2.cred.uuid, kresp2.cred.token);
}

static void unregister_valid_device_test(const void *user_data)
{
	int ipv6 = L_PTR_TO_INT(user_data);

	memset(&kmsg, 0, sizeof(kmsg));
	memset(&kresp, 0, sizeof(kresp));
	kmsg.hdr.type = KNOT_MSG_UNREG_REQ;

	kmsg.hdr.payload_len = 0;

	if (ipv6)
		assert(do_request6(&kmsg, sizeof(kmsg.unreg), &kresp) ==
						 sizeof(kresp.action));
	else
		assert(do_request4(&kmsg, sizeof(kmsg.unreg), &kresp) ==
						 sizeof(kresp.action));

	assert(kresp.hdr.payload_len == sizeof(kresp.action.result));
	assert(kresp.hdr.type == KNOT_MSG_UNREG_RSP);
	assert(kresp.action.result == 0);
}

/* Register and run all tests */
int main(int argc, char *argv[])
{
	int ipv6 = 0;
	signal(SIGPIPE, SIG_IGN);

	l_test_init(&argc, &argv);

	l_test_add("/1/register_missing_devname_ipv4",
				  register_missing_devname_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/2/register_empty_devname_ipv4",
				  register_empty_devname_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/3/register_valid_devname_ipv4",
				  register_valid_devname_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/4/register_repeated_attempt_ipv4",
				  register_repeated_attempt_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/5/register_new_id_ipv4",
				  register_new_id,
					L_INT_TO_PTR(ipv6));
	l_test_add("/6/authenticate_ipv4",
				  authenticate_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/7/unregister_valid_device_ipv4",
				  unregister_valid_device_test,
					L_INT_TO_PTR(ipv6));

	ipv6 = 1;

	l_test_add("/8/register_missing_devname_ipv6",
				  register_missing_devname_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/9/register_empty_devname_ipv6",
				  register_empty_devname_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/10/register_valid_devname_ipv6",
				  register_valid_devname_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/11/register_repeated_attempt_ipv6",
				  register_repeated_attempt_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/12/register_new_id_ipv6",
				  register_new_id,
					L_INT_TO_PTR(ipv6));
	l_test_add("/13/authenticate_ipv6",
				  authenticate_test,
					L_INT_TO_PTR(ipv6));
	l_test_add("/14/unregister_valid_device_ipv6",
				  unregister_valid_device_test,
					L_INT_TO_PTR(ipv6));

	return l_test_run();
}

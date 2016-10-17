/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2015, CESAR. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the CESAR nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CESAR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>

#include <glib.h>

#include <json-c/json.h>

#include "log.h"
#include "proto.h"

#define CURL_OP_TIMEOUT					30	/* 30 seconds */
#define URL_SIZE					128
#define REQUEST_SIZE					10
#define EXPECTED_RESPONSE_ARRAY_LENGTH			1

/* Credential registered on meshblu service */

/* UUID128 on string format:   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx */
#define MESHBLU_UUID_SIZE			36

/* Meshblu secret token: 40 chars */
#define MESHBLU_TOKEN_SIZE			40

#define DEFAULT_MESHBLU_SERVER_URI		"meshblu.octoblu.com"
#define MESHBLU_AUTH_UUID			"meshblu_auth_uuid: "
#define MESHBLU_AUTH_UUID_SIZE			sizeof(MESHBLU_AUTH_UUID)
#define MESHBLU_AUTH_TOKEN			"meshblu_auth_token: "
#define MESHBLU_AUTH_TOKEN_SIZE			sizeof(MESHBLU_AUTH_TOKEN)

static struct in_addr host_addr;
static unsigned int host_port;
static char *host_uri;
static char *device_uri;
static char *data_uri;

static int http2errno(long ehttp)
{
	switch (ehttp) {
	case 200: /* OK */
	case 201: /* Created */
		return 0;
	case 401: /* Unauthorized */
	case 403: /* Forbidden */
		return -EPERM;
	case 404: /* Not Found */
		return -ENOENT;
	}

	return -EIO;
}

static curl_socket_t opensocket(void *clientp, curlsocktype purpose,
						struct curl_sockaddr *address)
{
	/* Socket is passed through CURLOPT_OPENSOCKETDATA option */
	return *(curl_socket_t *) clientp;
}

static int sockopt_callback(void *clientp, curl_socket_t curlfd,
							curlsocktype purpose)
{
	/* This return code was added in libcurl 7.21.5 */
	return CURL_SOCKOPT_ALREADY_CONNECTED;
}

static int closesock_cb(void *clientp, curl_socket_t item)
{
	return CURLE_OK;
}

static size_t write_cb(void *contents, size_t size, size_t nmemb,
							void *user_data)
{
	json_raw_t *json = (json_raw_t *) user_data;
	size_t realsize = size * nmemb;

	json->data = (char *) realloc(json->data, json->size + realsize + 1);
	if (json->data == NULL) {
		LOG_ERROR("Not enough memory\n");
		return 0;
	}

	memcpy(json->data + json->size, contents, realsize);
	json->size += realsize;

	/* Forcing NULL terminated string */
	json->data[json->size] = 0;

	return realsize;
}

static int check_json(const char *json_str, json_raw_t *json)
{
	size_t realsize;
	const char *jobjstr;
	json_object *jobj, *jres, *jobjarray;

	jobj = json_tokener_parse(json_str);

	if (jobj == NULL)
		return -1;

	if (!json_object_object_get_ex(jobj, "devices", &jobjarray))
		return -1;

	if (json_object_get_type(jobjarray) != json_type_array ||
			json_object_array_length(jobjarray) !=
					EXPECTED_RESPONSE_ARRAY_LENGTH)
		return -1;

	jres = json_object_array_get_idx(jobjarray, 0);
	jobjstr = json_object_to_json_string(jres);

	realsize = strlen(jobjstr) + 1;

	json->data = (char *) realloc(json->data, realsize);
	if (json->data == NULL) {
		LOG_ERROR("Not enough memory\n");
		return -ENOMEM;
	}

	memcpy(json->data, jobjstr, realsize);
	json->size = realsize;
	json->data[json->size - 1] = 0;
	json_object_put(jobj);

	return 0;
}

/* Fetch and return url body via curl */
static int fetch_url(int sockfd, const char *action, const char *json,
			const char *uuid, const char *token,
			json_raw_t *fetch, const char *request)
{
	char token_hdr[MESHBLU_AUTH_TOKEN_SIZE + MESHBLU_TOKEN_SIZE];
	char uuid_hdr[MESHBLU_AUTH_UUID_SIZE + MESHBLU_UUID_SIZE];
	char upcase_request[REQUEST_SIZE + 1];
	struct curl_slist *headers = NULL;
	CURL *ch;
	CURLcode rcode;
	long ehttp;
	size_t i;

	if (!request || !fetch) {
		LOG_ERROR("Invalid argument!\n");
		return -EINVAL;
	}

	LOG_INFO("action: %s\n", action);

	ch = curl_easy_init();
	if (ch == NULL) {
		LOG_ERROR("curl_easy_init(): init failed\n");
		return -ENOMEM;
	}

	if (fetch->data)
		free(fetch->data);

	fetch->data = NULL;
	fetch->size = 0;

	strncpy(upcase_request, request, sizeof(upcase_request));
	for (i = 0; i < strlen(upcase_request); i++)
		upcase_request[i] = toupper(upcase_request[i]);

	curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, upcase_request);

	curl_easy_setopt(ch, CURLOPT_URL, action);

	LOG_INFO("HTTP(%s): %s\n", upcase_request, action);

	if (uuid && token) {

		snprintf(uuid_hdr, sizeof(uuid_hdr), "%s%s",
						MESHBLU_AUTH_UUID, uuid);
		headers = curl_slist_append(headers, uuid_hdr);
		snprintf(token_hdr, sizeof(token_hdr), "%s%s",
					MESHBLU_AUTH_TOKEN, token);
		headers = curl_slist_append(headers, token_hdr);
		LOG_INFO(" AUTH: %s\n       %s\n", uuid, token);
	}

	if (json) {
		headers = curl_slist_append(headers,
						"Accept: application/json");
		headers = curl_slist_append(headers,
					    "Content-Type: application/json");
		headers = curl_slist_append(headers, "charsets: utf-8");
		curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json);
		LOG_INFO(" JSON TX: %s\n", json);
	}

	if (headers)
		curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(ch, CURLOPT_WRITEDATA, fetch);
	curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");

	/* TODO: make sure that it is smaller than KNOT timeout */
	curl_easy_setopt(ch, CURLOPT_TIMEOUT, CURL_OP_TIMEOUT);
	curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1L);
	curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);

	if (sockfd > 0) {
		curl_easy_setopt(ch, CURLOPT_OPENSOCKETFUNCTION, opensocket);
		curl_easy_setopt(ch, CURLOPT_OPENSOCKETDATA, &sockfd);
		curl_easy_setopt(ch, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
		curl_easy_setopt(ch, CURLOPT_CLOSESOCKETFUNCTION, closesock_cb);
		curl_easy_setopt(ch, CURLOPT_CLOSESOCKETDATA, &sockfd);
	}

	rcode = curl_easy_perform(ch);

	curl_slist_free_all(headers);

	if (rcode != CURLE_OK) {
		curl_easy_cleanup(ch);
		LOG_ERROR("curl_easy_perform(): %s(%d)\n",
					curl_easy_strerror(rcode), rcode);
		return -EIO;
	}

	rcode = curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &ehttp);

	curl_easy_cleanup(ch);

	if (rcode != CURLE_OK) {
		LOG_ERROR("curl_easy_getinfo(): %s(%d)\n",
					curl_easy_strerror(rcode), rcode);
		return -EIO;
	}

	if (fetch->data)
		LOG_INFO(" JSON RX: %s\n", fetch->data);
	else
		LOG_INFO(" JSON RX: Empty\n");

	LOG_INFO("HTTP: %ld\n", ehttp);

	return http2errno(ehttp);
}

static int http_connect(void)
{
	struct sockaddr_in server;
	int sock, err;

	/*
	 * TODO: At the moment connect is blocking. Does it make
	 * sense to use asynchronous communication or use fork/pthread?
	 */
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		err = errno;
		LOG_ERROR("Meshblu socket(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = host_addr.s_addr;
	server.sin_port = htons(host_port);

	if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
		err = errno;
		LOG_ERROR("Meshblu connect(): %s(%d)\n", strerror(err), err);

		close(sock);
		return -err;
	}

	return sock;
}

static int http_mknode(int sock, const char *jreq, json_raw_t *json)
{
	/*
	 * HTTP 201: Created
	 * Return '0' if device has been created or a negative value
	 * mapped to generic Linux -errno codes.
	 */

	return fetch_url(sock, device_uri, jreq, NULL, NULL, json, "POST");

}

static int http_signin(int sock, const char *uuid, const char *token,
							json_raw_t *json)
{
	int err;
	/* Length: device_uri + '/' + UUID + '\0' */
	char uri[strlen(device_uri) + 2 + MESHBLU_UUID_SIZE];

	snprintf(uri, sizeof(uri), "%s/%s", device_uri, uuid);

	/*
	 * HTTP 200: OK
	 * Return '0' if signin not fails or a negative value
	 * mapped to generic Linux -errno codes.
	 */
	err = fetch_url(sock, uri, NULL, uuid, token, json, "GET");
	if (err < 0)
		return err;

	if (check_json(json->data, json) < 0)
		return -EINVAL;

	return err;
}

static int http_rmnode(int sock, const char *uuid, const char *token,
							json_raw_t *jbuf)
{
	/* Length: device_uri + '/' + UUID + '\0' */
	char uri[strlen(device_uri) + 2 + MESHBLU_UUID_SIZE];

	snprintf(uri, sizeof(uri), "%s/%s", device_uri, uuid);

	/*
	 * HTTP 200: OK
	 * Return '0' if rmnode not fails or a negative value
	 * mapped to generic Linux -errno codes.
	 */

	return fetch_url(sock, uri, NULL, uuid, token, jbuf, "DELETE");
}

static int http_schema(int sock, const char *uuid, const char *token,
					const char *jreq, json_raw_t *json)
{
	/* Length: device_uri + '/' + UUID + '\0' */
	char uri[strlen(device_uri) + 2 + MESHBLU_UUID_SIZE];

	snprintf(uri, sizeof(uri), "%s/%s", device_uri, uuid);

	/*
	 * HTTP 200: OK
	 * Return '0' if schema not fails or a negative value
	 * mapped to generic Linux -errno codes.
	 */

	return fetch_url(sock, uri, jreq, uuid, token, json, "PUT");
}

static int http_data(int sock, const char *uuid, const char *token,
					     const char *jreq, json_raw_t *json)
{
	/* Length: data_uri + '/' + UUID + '\0' */
	char uri[strlen(data_uri) + 2 + MESHBLU_UUID_SIZE];

	snprintf(uri, sizeof(uri), "%s/%s", data_uri, uuid);

	/*
	 * HTTP 200: OK
	 * Return '0' if data not fails or a negative value
	 * mapped to generic Linux -errno codes.
	 */

	return fetch_url(sock, uri, jreq, uuid, token, json, "POST");
}

static void http_close(int sock)
{

}

static int http_probe(const char *host, unsigned int port)
{
	struct hostent *hostent;
	int err;

	/* TODO: connect and track TCP socket */

	/* TODO: Add timer if it fails? */

	if (host)
		host_uri = g_strdup_printf("%s:%u", host, port);
	else
		host_uri = g_strdup_printf("%s:%u", DEFAULT_MESHBLU_SERVER_URI,
									port);

	host_port = port;
	device_uri = g_strdup_printf("%s/devices", host_uri);
	data_uri = g_strdup_printf("%s/data", host_uri);

	hostent = gethostbyname(host_uri);
	if  (hostent == NULL) {
		err = errno;
		LOG_ERROR("gethostbyname(%s): %s (%d)\n", host_uri,
						       strerror(err), err);
		return -err;
	}

	host_addr.s_addr = *((unsigned long *) hostent->h_addr_list[0]);

	LOG_INFO("Meshblu IP: %s\n", inet_ntoa(host_addr));

	return 0;
}

static void http_remove(void)
{
	g_free(host_uri);
	g_free(device_uri);
	g_free(data_uri);
}

struct proto_ops proto_http = {
	.name = "http",
	.probe = http_probe,
	.remove = http_remove,

	.connect = http_connect,
	.close = http_close,
	.mknode = http_mknode,
	.signin = http_signin,
	.rmnode = http_rmnode,
	.schema = http_schema,
	.data = http_data,
};

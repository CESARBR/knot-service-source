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
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>

#include "log.h"
#include "proto.h"

#define CURL_OP_TIMEOUT		10	/* 10 seconds */

#define MESHBLU_HOST		"meshblu.octoblu.com"
#define MESHBLU_DEV_URL		MESHBLU_HOST "/devices"
#define MESHBLU_DATA_URL	MESHBLU_HOST "/data/"

static struct in_addr host_addr;

static size_t write_cb(void *contents, size_t size, size_t nmemb,
							void *user_data)
{
	struct json_buffer *jbuf = (struct json_buffer *) user_data;
	size_t realsize = size * nmemb;

	jbuf->data = (char *) realloc(jbuf->data, jbuf->size + realsize + 1);
	if (jbuf->data == NULL) {
		LOG_ERROR("Not enough memory\n");
		return 0;
	}

	memcpy(jbuf->data + jbuf->size, contents, realsize);
	jbuf->size += realsize;

	/* Forcing NULL terminated string */
	jbuf->data[jbuf->size] = 0;

	return realsize;
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
	server.sin_port = htons(80);

	if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0){
		err = errno;
		LOG_ERROR("Meshblu connect(): %s(%d)\n", strerror(err), err);

		close(sock);
		return -err;
	}

	return sock;
}

static int http_signup(int sock, const char *owner_uuid,
					struct json_buffer *jbuf)
{
	CURL *curl;
	CURLcode res;
	char postfield[43];

	curl = curl_easy_init();
	if (curl == NULL)
		return -ENOMEM;

	snprintf(postfield, sizeof(postfield), "owner=%s", owner_uuid);

	curl_easy_setopt(curl, CURLOPT_URL, MESHBLU_DEV_URL);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfield);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

	/* TODO: make sure that it is smaller than KNOT timeout */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_OP_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, jbuf);
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sock);

	res = curl_easy_perform(curl);

	curl_easy_cleanup(curl);

	return (res == CURLE_OK  ? 0 : -EIO);
}

static int http_signin(int sock, const char *token)
{
	return -ENOSYS;
}

static void http_close(int sock)
{

}

static int http_get(int sock, const char *uuid, const char *token,
						struct json_buffer *jbuf)
{
	struct curl_slist *headers = NULL;
	char auth_uuid[55], auth_token[60];
	char data_url[strlen(MESHBLU_DATA_URL) + 38];
	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();
	if (curl == NULL)
		return -ENOMEM;

	snprintf(auth_uuid, sizeof(auth_uuid),
				"meshblu_auth_uuid:%s", uuid);
	snprintf(auth_token, sizeof(auth_token),
				"meshblu_auth_token:%s", token);
	snprintf(data_url, sizeof(data_url),
				"%s%s", MESHBLU_DATA_URL, uuid);

	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charsets: utf-8");
	headers = curl_slist_append(headers, auth_uuid);
	headers = curl_slist_append(headers, auth_token);

	curl_easy_setopt(curl, CURLOPT_URL, data_url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	/* TODO: make sure that it is smaller than KNOT timeout */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_OP_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, jbuf);
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sock);

	res = curl_easy_perform(curl);
	curl_slist_free_all(headers);

	curl_easy_cleanup(curl);

	return (res == CURLE_OK  ? 0 : -EIO);
}

static int http_post(int sock, const char *uuid, const char *token,
						const char *fields)
{
	char data_url[strlen(MESHBLU_DATA_URL) + 38];
	char auth_uuid[55], auth_token[60];
	struct curl_slist *headers = NULL;
	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();
	if(curl == NULL)
		return -ENOMEM;

	snprintf(data_url, sizeof(data_url), "%s%s", MESHBLU_DATA_URL, uuid);
	snprintf(auth_uuid, sizeof(auth_uuid), "meshblu_auth_uuid: %s", uuid);
	snprintf(auth_token, sizeof(auth_token), "meshblu_auth_token:%s",
									token);

	headers = curl_slist_append(headers, auth_uuid);
	headers = curl_slist_append(headers, auth_token);

	curl_easy_setopt(curl, CURLOPT_URL, data_url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	/* TODO: make sure that it is smaller than KNOT timeout */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_OP_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sock);

	res = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_slist_free_all(headers);

	return (res == CURLE_OK  ? 0 : -EIO);
}

static int http_probe(void)
{
	struct hostent *host;
	int err;

	/* TODO: connect and track TCP socket */

	/* TODO: Add timer if it fails? */
	host = gethostbyname(MESHBLU_HOST);
	if  (host == NULL) {
		err = errno;
		LOG_ERROR("gethostbyname(%s): %s (%d)\n", MESHBLU_HOST,
						       strerror(err), err);
		return -err;
	}

	host_addr.s_addr = *((unsigned long *) host-> h_addr_list[0]);

	LOG_INFO("Meshblu IP: %s\n", inet_ntoa(host_addr));

	return 0;
}

static void http_remove(void)
{
}

struct proto_ops proto_http = {
	.name = "http",
	.probe = http_probe,
	.remove = http_remove,

	.connect = http_connect,
	.close = http_close,
	.signup = http_signup,
	.signin = http_signin,
	.get = http_get,
	.post = http_post,
};

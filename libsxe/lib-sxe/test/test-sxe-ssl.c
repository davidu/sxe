/* Copyright (c) 2010 Sophos Group.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>   /* for getpid() on Linux */

#include "mock.h"
#include "sxe.h"
#include "sxe-log.h"
#include "sxe-socket.h"
#include "sxe-test.h"
#include "sxe-util.h"
#include "tap.h"

#define TEST_COPIES  10

#define S25 "abcdefghijklmnopqrstuvwxy"
#define S10 "0987654321"
#define S5  "~!@#$"
#define S100 S25 S10 S5 S25 S10 S25
#define S1000 S100 S100 S100 S100 S100 S100 S100 S100 S100 S100
#define S4000 S1000 S1000 S1000 S1000

const char *cert = "../test/test-sxe-ssl.cert";
const char *pkey = "../test/test-sxe-ssl.pkey";

tap_ev_queue q_server;
tap_ev_queue q_client;

static void
test_event_connected(SXE * this)
{
    tap_ev_queue q = SXE_USER_DATA(this);
    SXEE60I("test_event_connected()");
    tap_ev_queue_push(q, __func__, 1, "this", this);
    SXER60I("return");
}

static void
test_event_read(SXE * this, int length)
{
    SXE_UNUSED_PARAMETER(length);
    tap_ev_queue q = SXE_USER_DATA(this);
    SXEE61I("test_event_read(length=%d)", length);
    tap_ev_queue_push(q, __func__, 3,
                      "this", this,
                      "buf", tap_dup(SXE_BUF(this), SXE_BUF_USED(this)),
                      "used", SXE_BUF_USED(this));
    sxe_buf_clear(this);
    SXER60I("return");
}

static void
test_event_sent(SXE * this, SXE_RETURN final)
{
    tap_ev_queue q = SXE_USER_DATA(this);
    SXEE60I("test_event_sent()");
    tap_ev_queue_push(q, __func__, 2, "this", this, "result", final);
    SXER60I("return");
}

static void
test_event_close(SXE * this)
{
    tap_ev_queue q = SXE_USER_DATA(this);
    SXEE60I("test_event_close()");
    tap_ev_queue_push(q, __func__, 1, "this", this);
    SXER60I("return");
}

static void
tc_chat(const char *from, SXE * s_from, tap_ev_queue q_from, const char *sendbuf, size_t buflen,
        const char *to,   SXE * s_to,   tap_ev_queue q_to)
{
    SXE_RETURN   result;
    SXE_LIST     buflist;
    SXE_BUFFER   buffers[100];
    tap_ev       event;
    char       * readbuf;
    int          i;

    SXEA11((readbuf = calloc(TEST_COPIES, buflen)) != NULL,                             "Failed to allocate %u bytes", TEST_COPIES * buflen);

    SXE_LIST_CONSTRUCT(&buflist, 0, SXE_BUFFER, node);
    for (i = 0; i < TEST_COPIES; i++) {
        buffers[i].ptr  = sendbuf;
        buffers[i].len  = buflen;
        buffers[i].sent = 0;
        sxe_list_push(&buflist, &buffers[i]);
    }

    result = sxe_send_buffers(s_from, &buflist, test_event_sent);
    if (result == SXE_RETURN_IN_PROGRESS) {
        event = test_tap_ev_queue_shift_wait(q_from, 2);
        is_eq(tap_ev_identifier(event), "test_event_sent",                              "got %s sent event", from);
        is(SXE_CAST(SXE_RETURN, tap_ev_arg(event, "result")), SXE_RETURN_OK,            "got successful send");
    }
    else {
        skip(2, "%s sent immediately - no need to wait for sent event", from);
    }

    test_ev_queue_wait_read(q_to, 2, &event, s_to, "test_event_read", readbuf, TEST_COPIES * buflen, to);
    is_strncmp(sendbuf, readbuf, buflen,                                                "%s read contents from %s", to, from);

    free(readbuf);
}

static void
tc_chat_from_client(SXE * client, SXE * server, const char *buffer, size_t buflen)
{
    tc_chat("client", client, q_client, buffer, buflen,
            "server", server, q_server);
}

static void
tc_chat_from_server(SXE * client, SXE * server, const char *buffer, size_t buflen)
{
    tc_chat("server", server, q_server, buffer, buflen,
            "client", client, q_client);
}

int
main(int argc, char *argv[])
{
    tap_ev         event;
    SXE          * listener = NULL;
    SXE          * server   = NULL;
    SXE          * client   = NULL;

    SXE_UNUSED_PARAMETER(argc);

    q_server = tap_ev_queue_new();
    q_client = tap_ev_queue_new();

    plan_tests(59);

    sxe_log_set_level(SXE_LOG_LEVEL_LIBRARY_TRACE);
    sxe_register(6, 0);
    sxe_ssl_register(2);
    is(sxe_init(), SXE_RETURN_OK,                                                           "sxe_init succeeded");
    is(sxe_ssl_init(cert, pkey, cert, "."), SXE_RETURN_OK,                                  "sxe_ssl_init succeeded");

    listener = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);
    client   = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);
    SXE_USER_DATA(listener) = q_server;
    SXE_USER_DATA(client)   = q_client;

    /* Set up SSL on the listener and client. The listener doesn't actually
     * speak SSL, but any sockets it accepts will automatically inherit the
     * SSL flag, and will expect an SSL handshake to begin immediately. */
    is(sxe_ssl_enable(listener), SXE_RETURN_OK,                                         "sxe_ssl_enable succeeded");
    is(sxe_ssl_enable(client),   SXE_RETURN_OK,                                         "sxe_ssl_enable succeeded");

    SXEA10(sxe_listen(listener) == SXE_RETURN_OK,                                       "Failed to sxe_listen()");
    SXEA10(sxe_connect(client, "127.0.0.1", SXE_LOCAL_PORT(listener)) == SXE_RETURN_OK, "Failed to sxe_connect()");

    /* Ensure we get two connected events: one for the client and one for the
     * server. */
    event = test_tap_ev_queue_shift_wait(q_client, 2);
    is_eq(tap_ev_identifier(event), "test_event_connected",                             "got client connected event");
    event = test_tap_ev_queue_shift_wait(q_server, 2);
    is_eq(tap_ev_identifier(event), "test_event_connected",                             "got server connected event");
    server = SXE_CAST(SXE *, tap_ev_arg(event, "this"));

    /* Try to allocate another SSL connection; this will fail because we only
     * registered 2, and both are in use. */
    {
        SXE * extra = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);
        sxe_listen(extra);
        is(sxe_ssl_accept(extra), SXE_RETURN_NO_UNUSED_ELEMENTS,                            "got SXE_RETURN_NO_UNUSED_ELEMENTS");
        is(sxe_ssl_connect(extra), SXE_RETURN_NO_UNUSED_ELEMENTS,                           "got SXE_RETURN_NO_UNUSED_ELEMENTS");
        sxe_close(extra);
    }

    /* Try to use sxe_write() and sxe_sendfile() to prove that both refuse to
     * cooperate with SSL sockets. */
    {
        off_t offset;

        is(sxe_write(client, "Hello?", 6), SXE_RETURN_ERROR_WRITE_FAILED,                         "sxe_write() failed on SSL socket");
        is(sxe_sendfile(client, -1, &offset, 1, test_event_sent), SXE_RETURN_ERROR_WRITE_FAILED,  "sxe_sendfile() failed on SSL socket");
    }

    tc_chat_from_client(client, server, "HELO", 4);
    tc_chat_from_server(client, server, "HITHERE", 7);

    /* client -> server: something bigger than a single read, but only a
     * single write (16KB) */
    {
        char sendbuf[] = S4000;
        tc_chat_from_client(client, server, sendbuf, sizeof sendbuf);
        tc_chat_from_server(client, server, "THANKS!", 7);
    }

    /* client -> server: contents of a compiled program. */
    {
        struct stat   sb;
        char        * sendbuf;
        int           fd = open(argv[0], O_RDONLY);

        fstat(fd, &sb);
        sendbuf = malloc(sb.st_size);
        read(fd, sendbuf, sb.st_size);

        tc_chat_from_client(client, server, sendbuf, sb.st_size);
        tc_chat_from_server(client, server, "THANKS!", 7);

        close(fd);
        free(sendbuf);
    }

    /* Close the client, and ensure the server gets a close event. Note that
     * the client doesn't get a close event: SXE never generates close events
     * for explicit calls to sxe_close(), and SSL is no different. */
    {
        sxe_close(client);

        event = test_tap_ev_queue_shift_wait(q_server, 2);
        is_eq(tap_ev_identifier(event), "test_event_close",                                 "got server close event");
        is(tap_ev_arg(event, "this"), server,                                               "on the server");
    }

    /* Now connect the client and server again, and this time chat for a while
     * without SSL, then turn on SSL late and prove things keep working. */
    {
        listener = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);
        client   = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);
        SXE_USER_DATA(listener) = q_server;
        SXE_USER_DATA(client)   = q_client;
        SXEA10(sxe_listen(listener) == SXE_RETURN_OK,                                       "Failed to sxe_listen()");
        SXEA10(sxe_connect(client, "127.0.0.1", SXE_LOCAL_PORT(listener)) == SXE_RETURN_OK, "Failed to sxe_connect()");
        event = test_tap_ev_queue_shift_wait(q_client, 2);
        is_eq(tap_ev_identifier(event), "test_event_connected",                             "got client connected event");
        event = test_tap_ev_queue_shift_wait(q_server, 2);
        is_eq(tap_ev_identifier(event), "test_event_connected",                             "got server connected event");
        server = SXE_CAST(SXE *, tap_ev_arg(event, "this"));

        tc_chat_from_client(client, server, "HELLO", 5);
        tc_chat_from_server(client, server, "WORLD", 5);

        sxe_ssl_accept(server);
        sxe_ssl_connect(client);
        event = test_tap_ev_queue_shift_wait(q_client, 2);
        is_eq(tap_ev_identifier(event), "test_event_connected",                             "client: SSL session established");
        event = test_tap_ev_queue_shift_wait(q_server, 2);
        is_eq(tap_ev_identifier(event), "test_event_connected",                             "server: SSL session established");

        tc_chat_from_client(client, server, "BRIGADIER", 9);
        tc_chat_from_server(client, server, "GENERAL", 7);

        sxe_close(client);

        event = test_tap_ev_queue_shift_wait(q_server, 2);
        is_eq(tap_ev_identifier(event), "test_event_close",                                 "got server close event");
        is(tap_ev_arg(event, "this"), server,                                               "on the server");
    }

    is(sxe_fini(), SXE_RETURN_OK, "finished with sxe");

    return exit_status();
}

/* vim: set expandtab list sw=4 sts=4 listchars=tab\:^.,trail\:@: */

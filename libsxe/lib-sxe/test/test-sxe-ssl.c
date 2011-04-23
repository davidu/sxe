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
#include "sxe-mmap.h"
#include "sxe-socket.h"
#include "sxe-test.h"
#include "sxe-util.h"
#include "tap.h"

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

int
main(int argc, char *argv[])
{
    char           buffer[4096];
    tap_ev         event;
    SXE          * listener = NULL;
    SXE          * server   = NULL;
    SXE          * client   = NULL;
    SXE_RETURN     result;

    SXE_UNUSED_PARAMETER(argc);

    q_server = tap_ev_queue_new();
    q_client = tap_ev_queue_new();

    plan_tests(37);

    sxe_register(6, 0);
    sxe_ssl_register(2);
    is(sxe_init(), SXE_RETURN_OK,                                                           "sxe_init succeeded");
    is(sxe_ssl_init(cert, pkey, cert, "."), SXE_RETURN_OK,                                  "sxe_ssl_init succeeded");

    listener = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);
    client   = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);

    SXE_USER_DATA(listener) = q_server;
    SXE_USER_DATA(client)   = q_client;

    /* Set up the *listener* as an SSL server. The listener doesn't actually
     * do any SSL stuff, but this setting causes accepted sockets to
     * automatically begin speaking SSL. */
    {
        is(sxe_ssl_enable(listener), SXE_RETURN_OK,                                         "sxe_ssl_enable succeeded");
        SXEA10(sxe_listen(listener) == SXE_RETURN_OK,                                       "Failed to sxe_listen()");
    }

    /* Set up the client as an SSL client, and connect to the server. Ensure
     * we get two connected events: one for the client and one for the server.
     */
    {
        is(sxe_ssl_enable(client), SXE_RETURN_OK, "sxe_ssl_enable succeeded");
        SXEA10(sxe_connect(client, "127.0.0.1", SXE_LOCAL_PORT(listener)) == SXE_RETURN_OK, "Failed to sxe_connect()");

        event = test_tap_ev_queue_shift_wait(q_client, 2);
        is_eq(tap_ev_identifier(event), "test_event_connected",                             "got client connected event");

        event = test_tap_ev_queue_shift_wait(q_server, 2);
        is_eq(tap_ev_identifier(event), "test_event_connected",                             "got server connected event");

        /* Save the 'server' object for later tests */
        server = SXE_CAST(SXE *, tap_ev_arg(event, "this"));
    }

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

    /* client -> server: "HELO" */
    {
        result = sxe_send(client, "HELO", 4, test_event_sent);
        if (result == SXE_RETURN_IN_PROGRESS) {
            event = test_tap_ev_queue_shift_wait(q_client, 2);
            is_eq(tap_ev_identifier(event), "test_event_sent",                              "got client sent event");
            is_eq(SXE_CAST(SXE_RETURN, tap_ev_arg(event, "result")), SXE_RETURN_OK,         "got successful send");
        }
        else {
            skip(2, "client sent immediately - no need to wait for sent event");
        }

        test_ev_queue_wait_read(q_server, 2, &event, server, "test_event_read", buffer, 4, "server");
        is_strncmp(buffer, "HELO", 4,                                                       "server read 'HELO' from client");
    }

    /* server -> client: "HITHERE" */
    {
        result = sxe_send(server, "HITHERE", 7, test_event_sent);
        if (result == SXE_RETURN_IN_PROGRESS) {
            event = test_tap_ev_queue_shift_wait(q_server, 2);
            is_eq(tap_ev_identifier(event), "test_event_sent",                              "got server sent event");
            is_eq(SXE_CAST(SXE_RETURN, tap_ev_arg(event, "result")), SXE_RETURN_OK,         "got successful send");
        }
        else {
            skip(2, "server sent immediately - no need to wait for sent event");
        }

        test_ev_queue_wait_read(q_client, 2, &event, client, "test_event_read", buffer, 7, "client");
        is_strncmp(buffer, "HITHERE", 7,                                                    "client read 'HITHERE' from server");
    }

    /* client -> server: something bigger than a single read, but only a
     * single write (16KB) */
    {
#define S25 "abcdefghijklmnopqrstuvwxy"
#define S10 "0987654321"
#define S5  "~!@#$"
#define S100 S25 S10 S5 S25 S10 S25
#define S1000 S100 S100 S100 S100 S100 S100 S100 S100 S100 S100
#define S4000 S1000 S1000 S1000 S1000
        char sendbuf[] = S4000;

        result = sxe_send(client, sendbuf, sizeof sendbuf, test_event_sent);
        if (result == SXE_RETURN_IN_PROGRESS) {
            event = test_tap_ev_queue_shift_wait(q_client, 2);
            is_eq(tap_ev_identifier(event), "test_event_sent",                              "got client sent event");
            is_eq(SXE_CAST(SXE_RETURN, tap_ev_arg(event, "result")), SXE_RETURN_OK,         "got successful send");
        }
        else {
            skip(2, "client sent immediately - no need to wait for sent event");
        }

        test_ev_queue_wait_read(q_server, 2, &event, server, "test_event_read", buffer, sizeof sendbuf, "server");
        is_strncmp(buffer, sendbuf, sizeof sendbuf,                                         "server read correct content from client");
    }

    /* server -> client: "HITHERE" */
    {
        result = sxe_send(server, "THANKS!", 7, test_event_sent);
        if (result == SXE_RETURN_IN_PROGRESS) {
            event = test_tap_ev_queue_shift_wait(q_server, 2);
            is_eq(tap_ev_identifier(event), "test_event_sent",                              "got server sent event");
            is_eq(SXE_CAST(SXE_RETURN, tap_ev_arg(event, "result")), SXE_RETURN_OK,         "got successful send");
        }
        else {
            skip(2, "server sent immediately - no need to wait for sent event");
        }

        test_ev_queue_wait_read(q_client, 2, &event, client, "test_event_read", buffer, 7, "client");
        is_strncmp(buffer, "THANKS!", 7,                                                    "client read 'THANKS!' from server");
    }

    /* client -> server: contents of compiled argv[0]. */
    {
        char *readbuf;
        SXE_MMAP self;

        sxe_mmap_open(&self, argv[0]);
        SXEA11((readbuf = calloc(1, self.size)) != NULL,                                    "Failed to allocate %u bytes", self.size);

        result = sxe_send(client, self.addr, self.size, test_event_sent);
        is(result, SXE_RETURN_IN_PROGRESS,                                                  "got client send IN_PROGRESS");

        test_ev_queue_wait_read(q_server, 10, &event, server, "test_event_read", readbuf, self.size, "server");
        is(memcmp(readbuf, self.addr, self.size), 0,                                        "got correct contents of %s", argv[0]);

        event = test_tap_ev_queue_shift_wait(q_client, 2);
        is_eq(tap_ev_identifier(event), "test_event_sent",                                  "got client sent event");

        free(readbuf);
        sxe_mmap_close(&self);
    }

    /* Reply with something short from the server */
    {
        result = sxe_send(server, "THANKS!", 7, test_event_sent);
        if (result == SXE_RETURN_IN_PROGRESS) {
            event = test_tap_ev_queue_shift_wait(q_server, 2);
            is_eq(tap_ev_identifier(event), "test_event_sent",                              "got server sent event");
            is_eq(SXE_CAST(SXE_RETURN, tap_ev_arg(event, "result")), SXE_RETURN_OK,         "got successful send");
        }
        else {
            skip(2, "server sent immediately - no need to wait for sent event");
        }

        test_ev_queue_wait_read(q_client, 2, &event, client, "test_event_read", buffer, 7, "client");
        is_strncmp(buffer, "THANKS!", 7,                                                    "client read 'THANKS!' from server");
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

    is(sxe_fini(), SXE_RETURN_OK, "finished with sxe");

    return exit_status();
}

/* vim: set expandtab list sw=4 sts=4 listchars=tab\:^.,trail\:@: */

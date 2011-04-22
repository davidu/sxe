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
    tap_ev_queue q = SXE_USER_DATA(this);
    SXEE61I("test_event_read(length=%d)", length);
    tap_ev_queue_push(q, __func__, 2, "this", this, "length", length);
    SXER60I("return");
}

static void
test_event_sent(SXE * this, SXE_RETURN final)
{
    tap_ev_queue q = SXE_USER_DATA(this);
    SXEE60I("test_event_sent()");
    tap_ev_queue_push(q, __func__, 1, "this", this);
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
main(void)
{
    char           buffer[4096];
    tap_ev         event;
    unsigned       i;
    SXE          * listener = NULL;
    SXE          * server   = NULL;
    SXE          * client   = NULL;
    SXE_RETURN     result;

    q_server = tap_ev_queue_new();
    q_client = tap_ev_queue_new();

    plan_tests(20);
    sxe_register(6, 0);
    sxe_ssl_register(2);
    is(sxe_init(), SXE_RETURN_OK,                                                        "sxe_init succeeded");
    is(sxe_ssl_init(cert, pkey, cert, "."), SXE_RETURN_OK,                               "sxe_ssl_init succeeded");

    listener = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);
    client   = sxe_new_tcp(NULL, "0.0.0.0", 0, test_event_connected, test_event_read, test_event_close);

    SXE_USER_DATA(listener) = q_server;
    SXE_USER_DATA(client)   = q_client;

    /* Set up the *listener* as an SSL server. The listener doesn't actually
     * do any SSL stuff, but this setting causes accepted sockets to
     * automatically begin speaking SSL. */
    is(sxe_ssl_enable(listener), SXE_RETURN_OK, "sxe_ssl_enable succeeded");
    SXEA10(sxe_listen(listener) == SXE_RETURN_OK, "Failed to sxe_listen()");

    /* Set up the client as an SSL client. */
    is(sxe_ssl_enable(client), SXE_RETURN_OK, "sxe_ssl_enable succeeded");
    SXEA10(sxe_connect(client, "127.0.0.1", SXE_LOCAL_PORT(listener)) == SXE_RETURN_OK, "Failed to sxe_connect()");

    is_eq(tap_ev_identifier(event = test_tap_ev_queue_shift_wait(q_client, 2)), "test_event_connected", "got client connected event");
    is_eq(tap_ev_identifier(event = test_tap_ev_queue_shift_wait(q_server, 2)), "test_event_connected", "got server connected event");
    server = SXE_CAST(SXE *, tap_ev_arg(event, "this"));

    /* client -> server: "HELO" */
    result = sxe_send(client, "HELO", 4, test_event_sent);
    if (result == SXE_RETURN_IN_PROGRESS) {
        is_eq(tap_ev_identifier(event = test_tap_ev_queue_shift_wait(q_client, 2)), "test_event_sent", "got client sent event");
    }
    else {
        skip(1, "client sent immediately - no need to wait for sent event");
    }

    is_eq(tap_ev_identifier(event = test_tap_ev_queue_shift_wait(q_server, 2)), "test_event_read", "got server read event");
    is(SXE_CAST(int, tap_ev_arg(event, "length")), 4,                                   "read a four byte value");
    is(SXE_BUF_USED(server),     4,                                                     "four bytes in buffer");
    is_strncmp(SXE_BUF(server), "HELO", 4,                                              "'HELO' in buffer");

    /* server -> client: "GOODBYE" */
    result = sxe_send(server, "GOODBYE", 7, test_event_sent);
    if (result == SXE_RETURN_IN_PROGRESS) {
        is_eq(tap_ev_identifier(event = test_tap_ev_queue_shift_wait(q_server, 2)), "test_event_sent", "got server sent event");
    }
    else {
        skip(1, "server sent immediately - no need to wait for sent event");
    }
    is_eq(tap_ev_identifier(event = test_tap_ev_queue_shift_wait(q_client, 2)), "test_event_read", "got client read event");
    is(tap_ev_arg(event, "this"), client,                                           "on the client");
    is(SXE_CAST(int, tap_ev_arg(event, "length")), 7,                               "read a 7 byte value");
    is(SXE_BUF_USED(client),     7,                                                 "seven bytes in buffer");
    is_eq(SXE_BUF(client), "GOODBYE",                                   "'GOODBYE' in client buffer");

    sxe_close(client);
    is_eq(tap_ev_identifier(event = test_tap_ev_queue_shift_wait(q_server, 2)), "test_event_close",      "got server close event");
    is(tap_ev_arg(event, "this"), server,                                            "on the server");

    is(sxe_fini(), SXE_RETURN_OK, "finished with sxe");

    return exit_status();
}

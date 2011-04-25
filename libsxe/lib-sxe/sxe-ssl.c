#include <openssl/ssl.h>
#include <openssl/err.h>

#include "sxe.h"
#include "sxe-pool.h"

typedef enum SXE_SSL_STATE {
    SXE_SSL_S_FREE=0,
    SXE_SSL_S_CONNECTED,
    SXE_SSL_S_ESTABLISHED,
    SXE_SSL_S_READING,
    SXE_SSL_S_WRITING,
    SXE_SSL_S_CLOSING,
    SXE_SSL_S_NUMBER_OF_STATES
} SXE_SSL_STATE;

typedef enum SXE_SSL_MODE {
    SXE_SSL_M_INVALID=0,
    SXE_SSL_M_CLIENT,
    SXE_SSL_M_SERVER
} SXE_SSL_MODE;

typedef struct SXE_SSL {
    SSL          * conn;
    SXE_SSL_MODE   mode;
    int            verified;    /* was the peer certificate verified? */
    char           cipher[42];
    int            bits;
    char           version[42];
} SXE_SSL;

extern struct ev_loop        * sxe_private_main_loop;

static unsigned   sxe_ssl_total = 0;
static SXE_SSL  * sxe_ssl_array = NULL;
static SSL_CTX  * sxe_ssl_ctx   = NULL;

static void sxe_ssl_io_cb_write(EV_P_ ev_io *io, int revents);
static void sxe_ssl_io_cb_read(EV_P_ ev_io *io, int revents);

static const char *
sxe_ssl_state_to_string(SXE_SSL_STATE state)
{                                                           /* Coverage exclusion: state-to-string */
    switch (state) {                                        /* Coverage exclusion: state-to-string */
        case SXE_SSL_S_FREE        : return "FREE";         /* Coverage exclusion: state-to-string */
        case SXE_SSL_S_CONNECTED   : return "CONNECTED";    /* Coverage exclusion: state-to-string */
        case SXE_SSL_S_ESTABLISHED : return "ESTABLISHED";  /* Coverage exclusion: state-to-string */
        case SXE_SSL_S_READING     : return "READING";      /* Coverage exclusion: state-to-string */
        case SXE_SSL_S_WRITING     : return "WRITING";      /* Coverage exclusion: state-to-string */
        default:                     return NULL;           /* Coverage exclusion: state-to-string */
    }                                                       /* Coverage exclusion: state-to-string */
}                                                           /* Coverage exclusion: state-to-string */

void
sxe_ssl_register(unsigned number_of_connections)
{
    SXEE81("sxe_ssl_register(number_of_connections=%u)", number_of_connections);
    sxe_ssl_total += number_of_connections;
    SXER80("return");
}

SXE_RETURN
sxe_ssl_init(const char *cert_path, const char *key_path, const char *CAfile, const char *CAdir)
{
    SXE_RETURN       result = SXE_RETURN_OK;

    SXEE84("sxe_sxl_init(cert_path=%s,key_path=%s,CAfile=%s,CAdir=%s)",
            cert_path, key_path, CAfile ? CAfile : "(null)", CAdir ? CAdir : "(null)");

    SSL_load_error_strings();
    SSL_library_init();

    SXEL82("Allocating %u SXE_SSLs of %u bytes each", sxe_ssl_total, sizeof(SXE_SSL));
    sxe_ssl_array = sxe_pool_new("sxe_ssl_pool", sxe_ssl_total, sizeof(SXE_SSL), SXE_SSL_S_NUMBER_OF_STATES, 0);
    sxe_pool_set_state_to_string(sxe_ssl_array, sxe_ssl_state_to_string);

    ERR_clear_error();

    /* Use SSLv2 handshake, but only allow TLSv1 or SSLv3. */
    SXEA11((sxe_ssl_ctx = SSL_CTX_new(SSLv23_method())) != NULL, "Failed to create SSL context: %u", ERR_get_error());
    SSL_CTX_set_options(sxe_ssl_ctx, SSL_OP_NO_SSLv2);
    SXEA11(SSL_CTX_set_cipher_list(sxe_ssl_ctx, "HIGH;MEDIUM;!LOW;!EXPORT;!eNULL;!aNULL;!SSLv2") == 1,
            "Failed to set SSL context's cipher list: %u", ERR_get_error());

    /* Allow SSL_write() to return non-negative numbers after writing a single
     * SSL record. */
    SSL_CTX_set_mode(sxe_ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    SXEA11(SSL_CTX_use_certificate_file(sxe_ssl_ctx, cert_path, SSL_FILETYPE_PEM) == 1,
            "Failed to set SSL context's certificate file: %u", ERR_get_error());
    SXEA11(SSL_CTX_use_PrivateKey_file(sxe_ssl_ctx, key_path, SSL_FILETYPE_PEM) == 1,
            "Failed to set SSL context's PrivateKey file: %u", ERR_get_error());
    SXEA11(SSL_CTX_load_verify_locations(sxe_ssl_ctx, CAfile, CAdir) == 1,
            "Failed to set SSL context's verify locations: %u", ERR_get_error());

    /* Server mode: the server will not send a client certificate request to
     * the client, so the client will not send a certificate.
     *
     * Client mode: the server will send a certificate which will be checked.
     * The result of the certificate verification process can be checked after
     * the TLS/SSL handshake using the SSL_get_verify_result(3) function.  The
     * handshake will be continued regardless of the verification result.
     */
    SSL_CTX_set_verify(sxe_ssl_ctx, SSL_VERIFY_NONE, NULL);

    SXER82("return %d // %s", result, sxe_return_to_string(result));
    return result;
}

SXE_RETURN
sxe_ssl_enable(SXE * this)
{
    SXE_RETURN result = SXE_RETURN_OK;

    SXEE80I("sxe_ssl_enable()");

    SXEA11I(sxe_ssl_array != NULL, "SSL: cannot call %s() before sxe_ssl_init()", __func__);
    SXEA10I(this->flags & SXE_FLAG_IS_STREAM, "SXE is not a stream: cannot enable SSL");

    this->flags |= SXE_FLAG_IS_SSL;

    SXER82("return %d // %s", result, sxe_return_to_string(result));
    return result;
}

static SXE_RETURN
setup_ssl_socket(SXE * this)
{
    SXE_RETURN   result  = SXE_RETURN_ERROR_INTERNAL;
    SXE_SSL    * ssl = NULL;
    unsigned     id;

    SXEE80I("setup_ssl_socket()");

    if ((id = sxe_pool_set_oldest_element_state(sxe_ssl_array, SXE_SSL_S_FREE, SXE_SSL_S_CONNECTED)) == SXE_POOL_NO_INDEX) {
        SXEL30I("setup_ssl_socket: Warning: ran out of SSL connections; SSL concurrency too high");
        result = SXE_RETURN_NO_UNUSED_ELEMENTS;
        goto SXE_EARLY_OUT;
    }

    ssl = &sxe_ssl_array[id];
    memset(ssl, 0, sizeof *ssl);

    ssl->conn = SSL_new(sxe_ssl_ctx);
    SXEA11I(ssl->conn != NULL, "Failed to create new SSL connection: %u", ERR_get_error());
    SXEA11I(SSL_set_fd(ssl->conn, this->socket_as_fd) == 1, "Failed to set SSL file descriptor: %u", ERR_get_error());

    result       = SXE_RETURN_OK;
    this->ssl_id = id;

SXE_EARLY_OUT:
    SXER82I("return %d // %s", result, sxe_return_to_string(result));
    return result;
}

static void
close_ssl_socket(SXE * this, SXE_SSL_STATE state)
{
    SXEE81I("close_ssl_socket(state=%s)", sxe_ssl_state_to_string(state));

    sxe_pool_set_indexed_element_state(sxe_ssl_array, this->ssl_id, state, SXE_SSL_S_FREE);
    this->ssl_id = SXE_POOL_NO_INDEX;

    sxe_close(this);

    if (this->in_event_close) {
        (*this->in_event_close)(this);
    }

    SXER80("return");
}

static SXE_RETURN
handle_ssl_io_error(SXE * this, SXE_SSL *ssl, int ret,
                    SXE_SSL_STATE state, SXE_SSL_STATE read_state, SXE_SSL_STATE write_state,
                    const char *func, const char *op)
{
    SXE_RETURN   result = SXE_RETURN_ERROR_INTERNAL;
    char         errstr[1024];

    SXEE86I("handle_ssl_io_error(ret=%u,state=%s,read_state=%s,write_state=%s,func=%s,op=%s",
            ret, sxe_ssl_state_to_string(state), sxe_ssl_state_to_string(read_state),
            sxe_ssl_state_to_string(write_state), func, op);

    switch (SSL_get_error(ssl->conn, ret)) {
    case SSL_ERROR_WANT_READ:
        SXEL82I("%s(): %s() wants to read!", func, op);
        if (state != read_state) {
            sxe_pool_set_indexed_element_state(sxe_ssl_array, this->ssl_id, state, read_state);     /* Coverage exclusion: todo - get SSL_write() to return SSL_ERROR_WANT_READ */
        }
        sxe_watch_events(this, sxe_ssl_io_cb_read, EV_READ, 1);
        result = SXE_RETURN_IN_PROGRESS;
        break;

    case SSL_ERROR_WANT_WRITE:
        SXEL82I("%s(): %s() wants to write!", func, op);
        if (state != write_state) {
            sxe_pool_set_indexed_element_state(sxe_ssl_array, this->ssl_id, state, write_state);
        }
        sxe_watch_events(this, sxe_ssl_io_cb_write, EV_WRITE, 1);
        result = SXE_RETURN_IN_PROGRESS;
        break;

    case SSL_ERROR_ZERO_RETURN:
        /* The SSL transport has been closed cleanly. This does not
         * necessarily mean the underlying transport has been closed. Need to
         * do an sxe_close() here. */
        SXEL31I("%s(): SSL zero return: closing connection", func);
        close_ssl_socket(this, state);
        result = SXE_RETURN_END_OF_FILE;
        break;

    case SSL_ERROR_SSL:
        SXEL33I("%s(): %s() error: %u", func, op, ERR_error_string(ERR_get_error(), errstr));       /* Coverage exclusion: todo - get SSL function to return SSL_ERROR_SSL */
        close_ssl_socket(this, state);                                                              /* Coverage exclusion: todo - get SSL function to return SSL_ERROR_SSL */
        break;                                                                                      /* Coverage exclusion: todo - get SSL function to return SSL_ERROR_SSL */

    case SSL_ERROR_SYSCALL:
        {                                                                                           /* Coverage exclusion: todo - get SSL functions to fail in system calls */
            long err = ERR_get_error();                                                             /* Coverage exclusion: todo - get SSL functions to fail in system calls */
            if (err == 0) {                                                                         /* Coverage exclusion: todo - get SSL functions to fail in system calls */
                if (ret == 0) {                                                                     /* Coverage exclusion: todo - get SSL functions to fail in system calls */
                    SXEL31I("%s(): SSL received illegal EOF", func);                                /* Coverage exclusion: todo - get SSL functions to fail in system calls */
                }                                                                                   /* Coverage exclusion: todo - get SSL functions to fail in system calls */
                else {                                                                              /* Coverage exclusion: todo - get SSL functions to fail in system calls */
                    SXEL33I("%s(): SSL system call error: %s (%d)", func, strerror(errno), errno);  /* Coverage exclusion: todo - get SSL functions to fail in system calls */
                }                                                                                   /* Coverage exclusion: todo - get SSL functions to fail in system calls */
            }                                                                                       /* Coverage exclusion: todo - get SSL functions to fail in system calls */
            else {                                                                                  /* Coverage exclusion: todo - get SSL functions to fail in system calls */
                SXEL33I("%s(): %s(): SSL error %s", func, op, ERR_error_string(err, errstr));       /* Coverage exclusion: todo - get SSL functions to fail in system calls */
            }                                                                                       /* Coverage exclusion: todo - get SSL functions to fail in system calls */

            close_ssl_socket(this, state);                                                          /* Coverage exclusion: todo - get SSL functions to fail in system calls */
            result = SXE_RETURN_ERROR_WRITE_FAILED;                                                 /* Coverage exclusion: todo - get SSL functions to fail in system calls */
        }                                                                                           /* Coverage exclusion: todo - get SSL functions to fail in system calls */
        break;                                                                                      /* Coverage exclusion: todo - get SSL functions to fail in system calls */

    default:
        SXEL32I("%s(): %s(): returned unknown SSL error", func, op);                                /* Coverage exclusion: todo - get SSL functions to fail in other ways */
        close_ssl_socket(this, state);                                                              /* Coverage exclusion: todo - get SSL functions to fail in other ways */
        break;                                                                                      /* Coverage exclusion: todo - get SSL functions to fail in other ways */
    }

    SXER82("return %u // %s", result, sxe_return_to_string(result))
    return result;
}

static SXE_RETURN
do_ssl_handshake(SXE * this)
{
    SXE_RETURN   result = SXE_RETURN_ERROR_INTERNAL;
    SXE_SSL    * ssl;
    int          ret;
    unsigned     state;

    SXEE80I("do_ssl_handshake()");

    SXEA10I(this->ssl_id != SXE_POOL_NO_INDEX, "do_ssl_handshake(): socket is not SSL");
    state   = sxe_pool_index_to_state(sxe_ssl_array, this->ssl_id);
    SXEA11I(state == SXE_SSL_S_CONNECTED, "do_ssl_handshake(): SSL is in unexpected state '%s'", sxe_ssl_state_to_string(state));
    ssl = &sxe_ssl_array[this->ssl_id];

    ERR_clear_error();
    ret = SSL_do_handshake(ssl->conn);

    if (ret == 1) {
        const char *cipher, *version;

        /* The TLS/SSL handshake was successfully completed, a TLS/SSL
         * connection has been established. */
        SXEL80I("SSL connection established!");
        sxe_pool_set_indexed_element_state(sxe_ssl_array, this->ssl_id, SXE_SSL_S_CONNECTED, SXE_SSL_S_ESTABLISHED);
        result = SXE_RETURN_OK;

        if (ssl->mode == SXE_SSL_M_CLIENT) {
            X509 *peer;

            if (SSL_get_verify_result(ssl->conn) == X509_V_OK &&
                (peer = SSL_get_peer_certificate(ssl->conn)))
            {
                X509_free(peer);
                ssl->verified = 1;
            }
        }

        if ((cipher = SSL_get_cipher(ssl->conn))) {
            snprintf(ssl->cipher, sizeof ssl->cipher, "%s", cipher);
        }

        ssl->bits = SSL_get_cipher_bits(ssl->conn, NULL);

        if ((version = SSL_get_version(ssl->conn))) {
            snprintf(ssl->version, sizeof ssl->version, "%s", version);
        }

        if (this->in_event_connected) {
            (*this->in_event_connected)(this);
        }

        goto SXE_EARLY_OUT;
    }

    result = handle_ssl_io_error(this, ssl, ret, state, state, state, "do_ssl_handshake", "SSL_do_handshake");

SXE_EARLY_OUT:
    SXER82I("return %d // %s", result, sxe_return_to_string(result));
    return result;
}

SXE_RETURN
sxe_ssl_accept(SXE * this)
{
    SXE_RETURN   result;

    SXEE80I("sxe_ssl_accept()");
    SXEA11I(sxe_ssl_array != NULL, "SSL: cannot call %s() before sxe_ssl_init()", __func__);

    /* Allow calling sxe_ssl_accept() by an application on a non-SSL socket */
    sxe_ssl_enable(this);

    if ((result = setup_ssl_socket(this)) != SXE_RETURN_OK) {
        goto SXE_EARLY_OUT;
    }

    sxe_ssl_array[this->ssl_id].mode = SXE_SSL_M_SERVER;
    SSL_set_accept_state(sxe_ssl_array[this->ssl_id].conn);
    result = do_ssl_handshake(this);

SXE_EARLY_OUT:
    SXER82I("return %d // %s", result, sxe_return_to_string(result));
    return result;
}

SXE_RETURN
sxe_ssl_connect(SXE * this)
{
    SXE_RETURN   result;

    SXEE80I("sxe_ssl_connect()");
    SXEA11I(sxe_ssl_array != NULL, "SSL: cannot call %s() before sxe_ssl_init()", __func__);

    /* Allow calling sxe_ssl_accept() by an application on a non-SSL socket */
    sxe_ssl_enable(this);

    if ((result = setup_ssl_socket(this)) != SXE_RETURN_OK) {
        goto SXE_EARLY_OUT;
    }

    sxe_ssl_array[this->ssl_id].mode = SXE_SSL_M_CLIENT;
    SSL_set_connect_state(sxe_ssl_array[this->ssl_id].conn);
    result = do_ssl_handshake(this);

SXE_EARLY_OUT:
    SXER82I("return %d // %s", result, sxe_return_to_string(result));
    return result;
}

SXE_RETURN
sxe_ssl_close(SXE * this)
{
    SXE_RETURN    result = SXE_RETURN_OK;
    SXE_SSL     * ssl;
    SXE_SSL_STATE state;
    int           ret;

    SXEE80I("sxe_ssl_close()");

    SXEA10I(this->ssl_id != SXE_POOL_NO_INDEX, "sxe_ssl_close() called on non-SSL SXE");
    ssl = &sxe_ssl_array[this->ssl_id];
    state = sxe_pool_index_to_state(sxe_ssl_array, this->ssl_id);
    SXEA11I(state == SXE_SSL_S_ESTABLISHED || state == SXE_SSL_S_CLOSING,
            "sxe_ssl_close() in unexpected state %s", sxe_ssl_state_to_string(state));

    ERR_clear_error();
    ret = SSL_shutdown(ssl->conn);

    if (ret >= 0) {
        SXEL80I("SSL shut down");
        sxe_pool_set_indexed_element_state(sxe_ssl_array, this->ssl_id, state, SXE_SSL_S_FREE);
        this->ssl_id = SXE_POOL_NO_INDEX;
        sxe_close(this);
        goto SXE_EARLY_OUT;
    }

    result = handle_ssl_io_error(this, ssl, ret, state, SXE_SSL_S_CLOSING, SXE_SSL_S_CLOSING, "sxe_ssl_close", "SSL_shutdown"); /* Coverage exclusion: todo - get SSL_shutdown() to fail */

SXE_EARLY_OUT:
    SXER82I("return %d // %s", result, sxe_return_to_string(result));
    return result;
}

SXE_RETURN
sxe_ssl_send_buffers(SXE * this)
{
    SXE_RETURN    result  = SXE_RETURN_ERROR_INTERNAL;
    SXE_SSL     * ssl;
    SXE_BUFFER  * buffer;
    SXE_SSL_STATE state;

    SXEE81I("sxe_ssl_send_buffers() // SSL socket=%d", this->socket);

    SXEA10I(this->ssl_id != SXE_POOL_NO_INDEX, "sxe_ssl_send_buffers() called on non-SSL SXE");
    ssl = &sxe_ssl_array[this->ssl_id];
    state = sxe_pool_index_to_state(sxe_ssl_array, this->ssl_id);
    SXEA11I(state == SXE_SSL_S_ESTABLISHED || state == SXE_SSL_S_WRITING,
            "sxe_ssl_send_buffers() in unexpected state %s", sxe_ssl_state_to_string(state));

    buffer = sxe_list_walker_find(&this->send_list_walk);
    while (buffer) {
        const char * sendbuf = buffer->ptr + buffer->sent;
        int          trysend = buffer->len - buffer->sent;
        int          nbytes;

        ERR_clear_error();
        nbytes = SSL_write(ssl->conn, sendbuf, trysend);
        if (nbytes <= 0) {
            result = handle_ssl_io_error(this, ssl, nbytes, state, SXE_SSL_S_WRITING, SXE_SSL_S_WRITING, "sxe_ssl_send_buffers", "SSL_write");  /* Coverage exclusion: todo - get SSL_write() to fail */
            goto SXE_EARLY_OUT;
        }

        SXED90I(sendbuf, nbytes);
        buffer->sent += (size_t)nbytes;

        if (buffer->sent == buffer->len) {
            SXEL82I("All %u bytes written to SSL socket=%d; on to the next buffer", trysend, this->socket);
            buffer = sxe_list_walker_step(&this->send_list_walk);
        }
        else {
            SXEL83I("Only %u of %u bytes written to SSL socket=%d", nbytes, trysend, this->socket);
        }
    }

    /* We've written the last buffer: SXE_RETURN_OK */
    result = SXE_RETURN_OK;

    if (state != SXE_SSL_S_ESTABLISHED) {
        sxe_pool_set_indexed_element_state(sxe_ssl_array, this->ssl_id, state, SXE_SSL_S_ESTABLISHED);
        sxe_watch_events(this, sxe_ssl_io_cb_read, EV_READ, 1);
    }

SXE_EARLY_OUT:
    SXER82I("return %d // %s", result, sxe_return_to_string(result));
    return result;
}

static void
do_ssl_read(SXE * this)
{
    SXE_SSL     * ssl;
    int           nbytes;
    SXE_SSL_STATE state;

    SXEE81I("do_ssl_read() // SSL socket=%d", this->socket);

    SXEA10I(this->ssl_id != SXE_POOL_NO_INDEX, "do_ssl_read() called on non-SSL SXE");
    ssl = &sxe_ssl_array[this->ssl_id];
    state = sxe_pool_index_to_state(sxe_ssl_array, this->ssl_id);
    SXEA11I(state == SXE_SSL_S_ESTABLISHED || state == SXE_SSL_S_READING,
            "do_ssl_read() in unexpected state %s", sxe_ssl_state_to_string(state));

    for (;;) {
        ERR_clear_error();
        nbytes = SSL_read(ssl->conn, this->in_buf + this->in_total, sizeof(this->in_buf) - this->in_total);
        if (nbytes > 0) {
            sxe_handle_read_data(this, nbytes, NULL);
            continue;
        }

        handle_ssl_io_error(this, ssl, nbytes, state, SXE_SSL_S_ESTABLISHED, SXE_SSL_S_READING, "do_ssl_read", "SSL_read");
        break;
    }

    SXER80I("return");
    return;
}

static void
sxe_ssl_io_cb_read(EV_P_ ev_io *io, int revents)
{
    SXE           * this  = (SXE *)io->data;
    SXE_SSL_STATE   state;

    SXE_UNUSED_PARAMETER(loop);
    SXE_UNUSED_PARAMETER(revents);

    SXEE82I("sxe_ssl_io_cb_read(revents=%u) // socket=%d", revents, this->socket);

    SXEA10I(this->ssl_id != SXE_POOL_NO_INDEX, "sxe_ssl_io_cb_read() called on non-SSL SXE");
    state = sxe_pool_index_to_state(sxe_ssl_array, this->ssl_id);

    switch (state) {
    case SXE_SSL_S_CONNECTED:
        do_ssl_handshake(this);
        break;
    case SXE_SSL_S_ESTABLISHED:
    case SXE_SSL_S_READING:
        do_ssl_read(this);
        break;
    case SXE_SSL_S_WRITING:                                                                         /* Coverage exclusion: todo - make SSL_write() return SSL_ERROR_WANT_READ */
        sxe_ssl_send_buffers(this);                                                                 /* Coverage exclusion: todo - make SSL_write() return SSL_ERROR_WANT_READ */
        break;                                                                                      /* Coverage exclusion: todo - make SSL_write() return SSL_ERROR_WANT_READ */
    case SXE_SSL_S_CLOSING:                                                                         /* Coverage exclusion: todo - make SSL_shutdown() return SSL_ERROR_WANT_READ */
        sxe_ssl_close(this);                                                                        /* Coverage exclusion: todo - make SSL_shutdown() return SSL_ERROR_WANT_READ */
        break;                                                                                      /* Coverage exclusion: todo - make SSL_shutdown() return SSL_ERROR_WANT_READ */
    default:
        SXEA11I(0, "Unhandled sxe_ssl_io_cb_read() in state %s", sxe_ssl_state_to_string(state));   /* Coverage exclusion: can't happen without adding states. */
        break;
    }

    SXER80I("return");
}

static void
sxe_ssl_io_cb_write(EV_P_ ev_io *io, int revents)
{
    SXE_RETURN      result;
    SXE           * this  = (SXE *)io->data;
    SXE_SSL_STATE   state;

    SXE_UNUSED_PARAMETER(loop);
    SXE_UNUSED_PARAMETER(revents);

    SXEE82I("sxe_ssl_io_cb_write(revents=%u) // socket=%d", revents, this->socket);

    SXEA10I(this->ssl_id != SXE_POOL_NO_INDEX, "sxe_ssl_io_cb_write() called on non-SSL SXE");
    state = sxe_pool_index_to_state(sxe_ssl_array, this->ssl_id);

    switch (state) {
    case SXE_SSL_S_CONNECTED:                                                                       /* Coverage exclusion: todo - make SSL_do_handshake() return SSL_ERROR_WANT_WRITE */
        do_ssl_handshake(this);                                                                     /* Coverage exclusion: todo - make SSL_do_handshake() return SSL_ERROR_WANT_WRITE */
        break;                                                                                      /* Coverage exclusion: todo - make SSL_do_handshake() return SSL_ERROR_WANT_WRITE */
    case SXE_SSL_S_READING:                                                                         /* Coverage exclusion: todo - make SSL_read() return SSL_ERROR_WANT_WRITE */
        do_ssl_read(this);                                                                          /* Coverage exclusion: todo - make SSL_read() return SSL_ERROR_WANT_WRITE */
        break;                                                                                      /* Coverage exclusion: todo - make SSL_read() return SSL_ERROR_WANT_WRITE */
    case SXE_SSL_S_WRITING:
        result = sxe_ssl_send_buffers(this);
        if (result != SXE_RETURN_IN_PROGRESS) {
            if (this->out_event_written) {
                (*this->out_event_written)(this, result);
            }
        }
        break;
    case SXE_SSL_S_CLOSING:                                                                         /* Coverage exclusion: todo - make SSL_shutdown() return SSL_ERROR_WANT_WRITE */
        sxe_ssl_close(this);                                                                        /* Coverage exclusion: todo - make SSL_shutdown() return SSL_ERROR_WANT_WRITE */
        break;                                                                                      /* Coverage exclusion: todo - make SSL_shutdown() return SSL_ERROR_WANT_WRITE */
    default:
        SXEA11I(0, "Unhandled sxe_ssl_io_cb_write() in state %s", sxe_ssl_state_to_string(state));  /* Coverage exclusion: can't happen without adding states. */
        break;
    }

    SXER80("return");
}

/* vim: set expandtab list sw=4 sts=4 listchars=tab\:^.,trail\:@: */

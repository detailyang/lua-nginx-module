
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_ssl.h"
#include "ngx_http_lua_util.h"


#if (NGX_HTTP_SSL)


static int ngx_http_lua_ssl_ctx(lua_State *L);
static int ngx_http_lua_ssl_ctx_init(lua_State *L);
static ngx_int_t ngx_http_lua_ssl_ctx_create_method(
    const SSL_METHOD **ssl_method, ngx_str_t *method, const char **err);
static ngx_int_t ngx_http_lua_ssl_ctx_use_certificate(SSL_CTX *ctx,
    ngx_str_t *cert, const char **err, ngx_log_t *log);
static int ngx_http_lua_ssl_ctx_use_private_key(SSL_CTX *ctx,
    ngx_str_t *priv_key, ngx_str_t *password, const char **err, ngx_log_t *log);
static int ngx_http_lua_ssl_ctx_userdata_free(lua_State *L);
static void ngx_http_lua_ssl_ctx_set_default_options(SSL_CTX *ctx);
static int ngx_http_lua_ssl_password_callback(char *buf, int size, int rwflag,
    void *userdata);
static void ngx_http_lua_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn,
    int where, int ret);


#define ngx_http_lua_ssl_check_method(method, s)                            \
    ((method)->len == sizeof((s)) - 1                                       \
    && ngx_strncmp((method)->data, (s), sizeof((s)) - 1) == 0)


static char ngx_http_lua_ssl_ctx_metatable_key;
static char ngx_http_lua_ssl_ctx_userdata_metatable_key;


int ngx_http_lua_ssl_ctx_index = -1;


ngx_int_t
ngx_http_lua_ssl_init(ngx_log_t *log)
{
    if (ngx_http_lua_ssl_ctx_index == -1) {
        ngx_http_lua_ssl_ctx_index = SSL_get_ex_new_index(0, NULL, NULL,
                                                          NULL, NULL);

        if (ngx_http_lua_ssl_ctx_index == -1) {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                          "lua: SSL_get_ex_new_index() for ctx failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


void
ngx_http_lua_inject_ssl_api(lua_State *L)
{

    lua_createtable(L, 0, 1 /* nrec */);    /* ngx.ssl */

    lua_pushcfunction(L, ngx_http_lua_ssl_ctx);
    lua_setfield(L, -2, "ctx");

    /* {{{ssl ctx object metatable */
    lua_pushlightuserdata(L, &ngx_http_lua_ssl_ctx_metatable_key);
    lua_createtable(L, 0 /* narr */, 2 /* nrec */); /* metatable */

    lua_pushcfunction(L, ngx_http_lua_ssl_ctx_init);
    lua_setfield(L, -2, "init");

    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* {{{ssl ctx userdata metatable */
    lua_pushlightuserdata(L, &ngx_http_lua_ssl_ctx_userdata_metatable_key);
    lua_createtable(L, 0 /* narr */, 1 /* nrec */); /* metatable */

    lua_pushcfunction(L, ngx_http_lua_ssl_ctx_userdata_free);
    lua_setfield(L, -2, "__gc");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    lua_setfield(L, -2, "ssl");
}


static int
ngx_http_lua_ssl_ctx(lua_State *L)
{
    int     n;

    n = lua_gettop(L);
    if (n != 0) {
        return luaL_error(L, "expecting zero arguments, but got %d", n);
    }

    lua_createtable(L, 1 /* narr */, 1 /* nrec */);

    lua_pushlightuserdata(L, &ngx_http_lua_ssl_ctx_metatable_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    dd("top: %d", n);

    return 1;
}


static int
ngx_http_lua_ssl_ctx_init(lua_State *L)
{
    ngx_str_t                key_password = ngx_null_string;
    ngx_str_t                cert = ngx_null_string;
    ngx_str_t                priv_key = ngx_null_string;
    ngx_str_t                method = ngx_string("SSLv23_method");

    int                      n;
    SSL_CTX                 *ssl_ctx, **ud;
    const char              *err;
    const SSL_METHOD        *ssl_method;

    n = lua_gettop(L);
    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, but got %d", n);
    }

    /* check out the options table */
    luaL_checktype(L, -1, LUA_TTABLE);

    lua_getfield(L, -1, "method");

    switch (lua_type(L, -1)) {
        case LUA_TNIL:
            break;

        case LUA_TSTRING:
            method.data = (u_char *) lua_tolstring(L, -1, &method.len);
            break;

        default:
            return luaL_error(L, "bad \"method\" option value type: %s",
                              luaL_typename(L, -1));

    }

    lua_getfield(L, -2, "cert");

    switch (lua_type(L, -1)) {
        case LUA_TNIL:
            break;

        case LUA_TSTRING:
            cert.data = (u_char *) lua_tolstring(L, -1, &cert.len);
            break;

        default:
            return luaL_error(L, "bad \"cert\" option value type: %s",
                              luaL_typename(L, -1));

    }

    lua_getfield(L, -3, "key");

    switch (lua_type(L, -1)) {
        case LUA_TNIL:
            break;

        case LUA_TSTRING:
            priv_key.data = (u_char *) lua_tolstring(L, -1, &priv_key.len);
            break;

        default:
            return luaL_error(L, "bad \"key\" option value type: %s",
                              luaL_typename(L, -1));

    }

    lua_getfield(L, -4, "key_password");

    switch (lua_type(L, -1)) {
        case LUA_TNIL:
            break;

        case LUA_TSTRING:
            key_password.data = (u_char *) lua_tolstring(L, -1,
                                                         &key_password.len);
            break;

        default:
            return luaL_error(L, "bad \"key_password\" option value type: %s",
                              luaL_typename(L, -1));

    }

    lua_pop(L, 4);

    if (ngx_http_lua_ssl_ctx_create_method(&ssl_method,
                                       &method,
                                       &err) != NGX_OK)
    {
        lua_pushnil(L);
        lua_pushstring(L, err);
        return 2;
    }

    ssl_ctx = SSL_CTX_new(ssl_method);
    if (ssl_ctx == NULL) {
        err = "SSL_CTX_new() failed";
        ngx_ssl_error(NGX_LOG_EMERG, ngx_cycle->log, 0, (char *) err);

        lua_pushnil(L);
        lua_pushstring(L, err);
        return 2;
    }

    ngx_http_lua_ssl_ctx_set_default_options(ssl_ctx);

    ud = lua_newuserdata(L, sizeof(SSL_CTX *));
    *ud = ssl_ctx;

    /* set up the __gc metamethod */
    lua_pushlightuserdata(L, &ngx_http_lua_ssl_ctx_userdata_metatable_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);
    lua_rawseti(L, 1, SSL_CTX_INDEX);

    if (cert.len > 0) {
        if (ngx_http_lua_ssl_ctx_use_certificate(ssl_ctx,
                                                 &cert,
                                                 (const char **)&err,
                                                 ngx_cycle->log) != NGX_OK)
        {
            lua_pushnil(L);
            lua_pushstring(L, err);
            return 2;
        }
    }

    if (priv_key.len > 0) {
        if (ngx_http_lua_ssl_ctx_use_private_key(ssl_ctx,
                                                 &priv_key,
                                                 &key_password,
                                                 &err,
                                                 ngx_cycle->log) != NGX_OK)
        {
            lua_pushnil(L);
            lua_pushstring(L, err);
            return 2;
        }
    }

    lua_pushinteger(L, 1);

    return 1;
}


static int
ngx_http_lua_ssl_ctx_userdata_free(lua_State *L)
{
    SSL_CTX **pssl_ctx;

    pssl_ctx = lua_touserdata(L, 1);
    if (pssl_ctx == NULL || *pssl_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ssl ctx has been freed");
        return 0;
    }

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                  "free ssl ctx: %p:%d", *pssl_ctx, (*pssl_ctx)->references);

    /* SSL_CTX_free will free the following data
     * lh_SSL_SESSION_free(ctx->sessions);
     * X509_STORE_free(ctx->cert_store);
     * sk_SSL_CIPHER_free(ctx->cipher_list);
     * sk_SSL_CIPHER_free(ctx->cipher_list_by_id);
     * ssl_cert_free(ctx->cert);
     * sk_X509_NAME_pop_free(ctx->client_CA,X509_NAME_free);
     * sk_X509_pop_free(ctx->extra_certs,X509_free);
     * sk_SSL_COMP_pop_free(ctx->comp_methods,SSL_COMP_free);
     */

    SSL_CTX_free(*pssl_ctx);

    return 0;
}


static int
ngx_http_lua_ssl_password_callback(char *buf, int size, int rwflag,
    void *userdata)
{
    ngx_str_t *pwd = userdata;

    if (rwflag) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "ngx_http_lua_ssl_password_callback() "
                      "is called for encryption");
        return 0;
    }

    if (pwd->len == 0) {
        return 0;
    }

    if (pwd->len > (size_t) size) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "password is truncated to %d bytes", size);

    } else {
        size = pwd->len;
    }

    ngx_memcpy(buf, pwd->data, size);

    return size;
}


static ngx_int_t
ngx_http_lua_ssl_ctx_create_method(const SSL_METHOD **ssl_method,
    ngx_str_t *method, const char **err)
{
    if (ngx_http_lua_ssl_check_method(method, "SSLv23_method")) {
        *ssl_method = SSLv23_method();

    } else if (ngx_http_lua_ssl_check_method(method, "SSLv2_method")) {
        *err = "SSLv2 methods disabled";
        return NGX_ERROR;

    } else if (ngx_http_lua_ssl_check_method(method, "SSLv2_server_method")) {
        *err = "SSLv2 methods disabled";
        return NGX_ERROR;

    } else if (ngx_http_lua_ssl_check_method(method, "SSLv2_client_method")) {
        *err = "SSLv2 methods disabled";
        return NGX_ERROR;

    } else if (ngx_http_lua_ssl_check_method(method, "SSLv3_method")) {
        *err = "SSLv3 methods disabled";
        return NGX_ERROR;

    } else if (ngx_http_lua_ssl_check_method(method, "SSLv3_server_method")) {
        *err = "SSLv3 methods disabled";
        return NGX_ERROR;

    } else if (ngx_http_lua_ssl_check_method(method, "SSLv3_client_method")) {
        *err = "SSLv3 methods disabled";
        return NGX_ERROR;

    } else if (ngx_http_lua_ssl_check_method(method, "SSLv23_server_method")) {
        *ssl_method = SSLv23_server_method();

    } else if (ngx_http_lua_ssl_check_method(method, "SSLv23_client_method")) {
        *ssl_method = SSLv23_client_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_method")) {
        *ssl_method = TLSv1_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_server_method")) {
        *ssl_method = TLSv1_server_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_client_method")) {
        *ssl_method = TLSv1_client_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_1_method")) {
        *ssl_method = TLSv1_1_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_1_server_method")) {
        *ssl_method = TLSv1_1_server_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_1_client_method")) {
        *ssl_method = TLSv1_1_client_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_2_method")) {
        *ssl_method = TLSv1_2_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_2_server_method")) {
        *ssl_method = TLSv1_2_server_method();

    } else if (ngx_http_lua_ssl_check_method(method, "TLSv1_2_client_method")) {
        *ssl_method = TLSv1_2_client_method();

    } else {
        *err = "Unknown method";
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_lua_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn,
    int where, int ret)
{
    BIO               *rbio, *wbio;
    ngx_connection_t  *c;

    if (where & SSL_CB_HANDSHAKE_START) {
        c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

        if (c->ssl->handshaked) {
            c->ssl->renegotiation = 1;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL renegotiation");
        }
    }

    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
        c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

        if (!c->ssl->handshake_buffer_set) {
            /*
             * By default OpenSSL uses 4k buffer during a handshake,
             * which is too low for long certificate chains and might
             * result in extra round-trips.
             *
             * To adjust a buffer size we detect that buffering was added
             * to write side of the connection by comparing rbio and wbio.
             * If they are different, we assume that it's due to buffering
             * added to wbio, and set buffer size.
             */

            rbio = SSL_get_rbio((ngx_ssl_conn_t *) ssl_conn);
            wbio = SSL_get_wbio((ngx_ssl_conn_t *) ssl_conn);

            if (rbio != wbio) {
                (void) BIO_set_write_buffer_size(wbio, NGX_SSL_BUFSIZE);
                c->ssl->handshake_buffer_set = 1;
            }
        }
    }
}


static void
ngx_http_lua_ssl_ctx_set_default_options(SSL_CTX *ctx)
{
    /* {{{copy nginx ssl secure options */

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
    SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
    SSL_CTX_set_options(ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
#endif

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    SSL_CTX_set_options(ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
#endif

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
    /* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
    SSL_CTX_set_options(ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    SSL_CTX_set_options(ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
#endif

#ifdef SSL_OP_TLS_D5_BUG
    SSL_CTX_set_options(ctx, SSL_OP_TLS_D5_BUG);
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
    SSL_CTX_set_options(ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

#ifdef SSL_CTRL_CLEAR_OPTIONS
    /* only in 0.9.8m+ */
    SSL_CTX_clear_options(ctx,
                          SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
#endif

#ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1_1);
#endif

#ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1_2);
#endif

#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef SSL_MODE_NO_AUTO_CHAIN
    SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN);
#endif
    /* }}} */

    /* Disable SSLv2 in the case when method == SSLv23_method() and the
     * cipher list contains SSLv2 ciphers (not the default, should be rare)
     * The bundled OpenSSL doesn't have SSLv2 support but the system OpenSSL may
     * SSLv3 is disabled because it's susceptible to downgrade attacks
     */

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

    /* read as many input bytes as possible (for non-blocking reads) */
    SSL_CTX_set_read_ahead(ctx, 1);

    SSL_CTX_set_info_callback(ctx, ngx_http_lua_ssl_info_callback);
}


static ngx_int_t
ngx_http_lua_ssl_ctx_use_certificate(SSL_CTX *ctx, ngx_str_t *cert,
    const char **err, ngx_log_t *log)
{
    BIO            *bio;
    X509           *x509;
    u_long          n;

    bio = BIO_new_mem_buf((char *) cert->data, cert->len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        ngx_ssl_error(NGX_LOG_ERR, log, 0, (char *) *err);
        return NGX_ERROR;
    }

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        *err = "PEM_read_bio_X509_AUX failed";
        ngx_ssl_error(NGX_LOG_EMERG, log, 0, (char *) *err);
        BIO_free(bio);
        return NGX_ERROR;
    }

    if (SSL_CTX_use_certificate(ctx, x509) == 0) {
        *err = "SSL_CTX_use_certificate() failed";
        ngx_ssl_error(NGX_LOG_EMERG, log, 0, (char *) *err);
        X509_free(x509);
        BIO_free(bio);
        return NGX_ERROR;
    }

    /* read rest of the chain */

    for ( ;; ) {

        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509() failed";
            ngx_ssl_error(NGX_LOG_EMERG, log, 0, (char *) *err);
            BIO_free(bio);
            return NGX_ERROR;
        }

#ifdef SSL_CTRL_CHAIN_CERT

        /*
         * SSL_CTX_add0_chain_cert() is needed to add chain to
         * a particular certificate when multiple certificates are used;
         * only available in OpenSSL 1.0.2+
         */

        if (SSL_CTX_add0_chain_cert(ctx, x509) == 0) {
            *err = "SSL_CTX_add0_chain_cert() failed";
            ngx_ssl_error(NGX_LOG_EMERG, log, 0, (char *) *err);
            X509_free(x509);
            BIO_free(bio);
            return NGX_ERROR;
        }

#else

        if (SSL_CTX_add_extra_chain_cert(ctx, x509) == 0) {
            *err = "SSL_CTX_add_extra_chain_cert() failed";
            ngx_ssl_error(NGX_LOG_EMERG, log, 0, (char *) *err);
            X509_free(x509);
            BIO_free(bio);
            return NGX_ERROR;
        }

#endif
    }

    BIO_free(bio);

    return NGX_OK;
}


static int
ngx_http_lua_ssl_ctx_use_private_key(SSL_CTX *ctx, ngx_str_t *priv_key,
    ngx_str_t *password, const char **err, ngx_log_t *log)
{
    BIO         *bio;
    EVP_PKEY    *pkey;

    bio = BIO_new_mem_buf((char *) priv_key->data, priv_key->len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        ngx_ssl_error(NGX_LOG_ERR, log, 0, (char *) *err);
        return NGX_ERROR;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL,
                                   ngx_http_lua_ssl_password_callback,
                                   (void *) password);
    if (pkey == NULL) {
        BIO_free(bio);
        *err = "PEM_read_bio_PrivateKey() failed";
        ngx_ssl_error(NGX_LOG_ERR, log, 0, (char *) *err);
        return NGX_ERROR;
    }

    BIO_free(bio);

    if (!SSL_CTX_use_PrivateKey(ctx, pkey)) {
        EVP_PKEY_free(pkey);
        *err = "SSL_CTX_use_PrivateKey() failed";
        ngx_ssl_error(NGX_LOG_ERR, log, 0, (char *) *err);
        return NGX_ERROR;
    }

    EVP_PKEY_free(pkey);

    return NGX_OK;
}


#endif /* NGX_HTTP_SSL */

# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;
use Digest::MD5 qw(md5_hex);

repeat_each(2);

plan tests => repeat_each() * (blocks() + 12);

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();

sub read_file {
    my $infile = shift;
    open my $in, $infile
        or die "cannot open $infile for reading: $!";
    my $cert = do { local $/; <$in> };
    close $in;
    $cert;
}

our $StartComRootCertificate = read_file("t/cert/startcom.crt");
our $EquifaxRootCertificate = read_file("t/cert/equifax.crt");
our $TestCertificate = read_file("t/cert/test.crt");
our $TestCertificateKey = read_file("t/cert/test.key");
our $TestCRL = read_file("t/cert/test.crl");
our $clientKey = read_file("t/cert/client.key");
our $clientUnsecureKey = read_file("t/cert/client.unsecure.key");
our $clientCrt = read_file("t/cert/client.crt");
our $clientCrtMd5 = md5_hex($clientCrt);
our $serverKey = read_file("t/cert/server.key");
our $serverUnsecureKey = read_file("t/cert/server.unsecure.key");
our $serverCrt = read_file("t/cert/server.crt");
our $caKey = read_file("t/cert/ca.key");
our $caCrt = read_file("t/cert/ca.crt");
our $sslhttpconfig = <<_EOS_;
init_by_lua_block {
    function read_file(file)
        local f = io.open(file, "rb")
        local content = f:read("*all")
        f:close()
        return content
    end

    function get_response_body(response)
        for k, v in ipairs(response) do
            if #v == 0 then
                return table.concat(response, "\\r\\n", k + 1)
            end
        end

        return nil, "CRLF not found"
    end

    function https_get(host, port, path, ssl_ctx)
        local sock = ngx.socket.tcp()
        local ok, err = sock:setsslctx(ssl_ctx)
        if not ok then
            return nil, err
        end

        local ok, err = sock:connect(host, port)
        if not ok then
            return nil, err
        end

        local sess, err = sock:sslhandshake()
        if not sess then
            return nil, err
        end

        local req = "GET " .. path .. " HTTP/1.0\\r\\nHost: server\\r\\nConnection: close\\r\\n\\r\\n"
        local bytes, err = sock:send(req)
        if not bytes then
            return nil, err
        end

        local response = {}
        while true do
            local line, err, partial = sock:receive()
            if not line then
                if not partial then
                    response[#response+1] = partial
                end
                break
            end

            response[#response+1] = line
        end

        sock:close()

        return response
    end
}
server {
    listen 1983 ssl;
    server_name   server;
    ssl_certificate ../html/server.crt;
    ssl_certificate_key ../html/server.unsecure.key;

    server_tokens off;
    more_clear_headers Date;
    default_type 'text/plain';

    location / {
        content_by_lua_block {
            ngx.say("foo")
        }
    }

    location /protocol {
        content_by_lua_block {ngx.say(ngx.var.ssl_protocol)}
    }

    location /cert {
        content_by_lua_block {
            ngx.say(ngx.md5(ngx.var.ssl_client_raw_cert))
        }
    }
}
_EOS_
our $certfiles = <<_EOS_;
>>> client.key
$clientKey
>>> client.unsecure.key
$clientUnsecureKey
>>> client.crt
$clientCrt
>>> server.key
$serverKey
>>> server.unsecure.key
$serverUnsecureKey
>>> server.crt
$serverCrt
>>> ca.key
$caKey
>>> ca.crt
$caCrt
>>> wrong.crt
OpenResty
>>> wrong.key
OpenResty
_EOS_

run_tests();

__DATA__

=== TEST 1: sslctx:init wrong formated certificate
--- http_config eval: $::sslhttpconfig
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER ipv6=off;

    location /t {
        content_by_lua_block {
            local cert = read_file("$TEST_NGINX_HTML_DIR/wrong.crt")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                cert = cert,
            })
        }
    }

--- request
GET /t

--- ignore_response
--- user_files eval: $::certfiles
--- error_log eval
qr/.*PEM routines:PEM_read_bio:no start line:Expecting: TRUSTED CERTIFICATE.*/
--- timeout: 5



=== TEST 2: sslctx:init wrong formated key
--- http_config eval: $::sslhttpconfig
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER ipv6=off;

    location /t {
        content_by_lua_block {
            local key = read_file("$TEST_NGINX_HTML_DIR/wrong.key")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                key = key,
            })
        }
    }

--- request
GET /t

--- ignore_response
--- user_files eval: $::certfiles
--- error_log eval
qr/.*PEM routines:PEM_read_bio:no start line:Expecting: ANY PRIVATE KEY.*/
--- timeout: 5



=== TEST 3: sslctx:init with wrong password key
--- http_config eval: $::sslhttpconfig
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER ipv6=off;

    location /t {
        content_by_lua_block {
            local key = read_file("$TEST_NGINX_HTML_DIR/client.key")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                key = key,
                key_password = "wrongpassword"
            })
            if not ok then
                ngx.print("init ssl ctx error: ", err)
                return
            end
        }
    }

--- request
GET /t

--- response_body: init ssl ctx error: PEM_read_bio_PrivateKey() failed

--- user_files eval: $::certfiles
--- error_log eval
qr/.*digital envelope routines:EVP_DecryptFinal_ex:bad decrypt error.*/



=== TEST 4: sslctx:init disable ssl protocols method SSLv2 SSLv3
--- http_config eval: $::sslhttpconfig
--- config
    location /t {
        content_by_lua_block {
            local key = read_file("$TEST_NGINX_HTML_DIR/client.key")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                method = "SSLv2_method",
                key = key,
                key_password = "openresty"
            })
            if not ok then
                ngx.say('init ssl ctx error: ', err)
            end

            local ok, err = ssl_ctx:init({
                method = "SSLv3_method",
                key = key,
                key_password = "openresty"
            })
            if not ok then
                ngx.say('init ssl ctx error: ', err)
            end
        }
    }

--- request
GET /t

--- response_body eval
"init ssl ctx error: SSLv2 methods disabled
init ssl ctx error: SSLv3 methods disabled
"

--- user_files eval: $::certfiles
--- no_error_log
[error]



=== TEST 5: sslctx:init specify ssl protocols method TLSv1
--- http_config eval: $::sslhttpconfig
--- config
    location /t {
        content_by_lua_block {
            local key = read_file("$TEST_NGINX_HTML_DIR/client.key")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                method = "TLSv1_method",
                key = key,
                key_password = "openresty"
            })
            if not ok then
                ngx.print("init ssl ctx error: ", err)
                return
            end

            local response, err = https_get('127.0.0.1', 1983, '/protocol', ssl_ctx)

            if not response then
                ngx.say("send https request error: ", err)
                return
            end

            local body, err = get_response_body(response)
            if not body then
                ngx.say("get response body: ", err)
                return
            end

            ngx.print("body: ", body)
        }
    }

--- request
GET /t

--- response_body: body: TLSv1
--- user_files eval: $::certfiles
--- no_error_log
[error]
--- timeout: 5



=== TEST 6: sslctx:init specify ssl protocols method TLSv1.1
--- http_config eval: $::sslhttpconfig
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER ipv6=off;

    location /t {
        content_by_lua_block {
            local key = read_file("$TEST_NGINX_HTML_DIR/client.key")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                method = "TLSv1_1_method",
                key = key,
                key_password = "openresty"
            })
            if not ok then
                ngx.print("init ssl ctx error: ", err)
                return
            end

            local response, err = https_get('127.0.0.1', 1983, '/protocol', ssl_ctx)

            if not response then
                ngx.say("send https request error: ", err)
                return
            end

            local body, err = get_response_body(response)
            if not body then
                ngx.say("get response body: ", err)
                return
            end

            ngx.print("body: ", body)
        }
    }

--- request
GET /t

--- response_body: body: TLSv1.1
--- user_files eval: $::certfiles
--- no_error_log
[error]



=== TEST 7: sslctx:init specify ssl protocols method TLSv1.2
--- http_config eval: $::sslhttpconfig
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER ipv6=off;

    location /t {
        content_by_lua_block {
            local key = read_file("$TEST_NGINX_HTML_DIR/client.key")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                method = "TLSv1_2_method",
                key = key,
                key_password = "openresty"
            })
            if not ok then
                ngx.print("init ssl ctx error: ", err)
                return
            end

            local response, err = https_get('127.0.0.1', 1983, '/protocol', ssl_ctx)

            if not response then
                ngx.say("send https request error: ", err)
                return
            end

            local body, err = get_response_body(response)
            if not body then
                ngx.say("get response body: ", err)
                return
            end

            ngx.print("body: ", body)
        }
    }

--- request
GET /t

--- response_body: body: TLSv1.2
--- user_files eval: $::certfiles
--- no_error_log
[error]



=== TEST 8: sslctx:init set the trusted CA certificates
--- http_config eval: $::sslhttpconfig
--- config
    location /t {
        content_by_lua_block {
            local cacert = read_file("$TEST_NGINX_HTML_DIR/ca.crt")
            local wrongcert = read_file("$TEST_NGINX_HTML_DIR/wrong.crt")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                cacert = cacert
            })
            if not ok then
                ngx.say('init ssl ctx error: ', err)
            end

            ngx.say('init ssl ctx success for ca cert')
        }
    }

--- request
GET /t

--- response_body eval
"init ssl ctx success for ca cert
"

--- user_files eval: $::certfiles
--- no_error_log
[error]

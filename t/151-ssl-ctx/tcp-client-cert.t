# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;
use Digest::MD5 qw(md5_hex);

repeat_each(2);

plan tests => repeat_each() * (blocks() + 3);

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
                return table.concat(response, "\\r\\n", k + 1, #response - 1)
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
                if partial then
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
    ssl_client_certificate ../html/ca.crt;
    ssl_verify_client on;

    server_tokens off;

    location / {
        default_type 'text/plain';
        content_by_lua_block {
            ngx.say("foo")
        }
        more_clear_headers Date;
    }

    location /cert {
        default_type 'text/plain';
        content_by_lua_block {
            ngx.say(ngx.md5(ngx.var.ssl_client_raw_cert))
        }
        more_clear_headers Date;
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
_EOS_

run_tests();

__DATA__

=== TEST 1: setsslctx - expecting the two arguments
--- config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    location /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            local ok, err = sock:setsslctx()
        }
    }

--- request
GET /t

--- ignore_response
--- error_log eval
qr/\[error\] .* ngx.socket setsslctx: expecting 2 arguments \(including the object\), but seen 1/



=== TEST 2: setsslctx - no ssl ctx found
--- config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    location /t {
        content_by_lua_block {
            local fake_ssl_ctx = {}
            local sock = ngx.socket.tcp()
            local ok, err = sock:setsslctx(fake_ssl_ctx)
            if not ok then
                ngx.say("error: ", err)
            else
                ngx.say("success:", ok)
            end
        }
    }

--- request
GET /t

--- response_body eval
"error: no ssl ctx found
"



=== TEST 3: send client certificate with nopassword private key
--- http_config eval: $::sslhttpconfig
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER ipv6=off;

    location /t {
        content_by_lua_block {
            local cert = read_file("$TEST_NGINX_HTML_DIR/client.crt")
            local key = read_file("$TEST_NGINX_HTML_DIR/client.unsecure.key")
            local cacert = read_file("$TEST_NGINX_HTML_DIR/ca.crt")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                key = key,
                cert = cert,
                cacert = cacert
            })
            if not ok then
                ngx.say("failed to init ssl ctx: ", err)
                return
            end

            response = https_get("127.0.0.1", 1983, "/cert", ssl_ctx)
            ngx.say(get_response_body(response))
        }
    }

--- request
GET /t

--- response_body eval
"$::clientCrtMd5
"

--- user_files eval: $::certfiles



=== TEST 4: setsslctx - send client certificate with password private key
--- http_config eval: $::sslhttpconfig
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER ipv6=off;

    location /t {
        content_by_lua_block {
            local cert = read_file("$TEST_NGINX_HTML_DIR/client.crt")
            local key = read_file("$TEST_NGINX_HTML_DIR/client.key")
            local cacert = read_file("$TEST_NGINX_HTML_DIR/ca.crt")

            local ssl_ctx = ngx.ssl.ctx()
            local ok, err = ssl_ctx:init({
                key = key,
                key_password = "openresty",
                cert = cert,
                cacert = cacert
            })
            if not ok then
                ngx.say("failed to init ssl ctx: ", err)
                return
            end

            response = https_get("127.0.0.1", 1983, "/cert", ssl_ctx)
            ngx.say(get_response_body(response))
        }
    }

--- request
GET /t

--- response_body eval
"$::clientCrtMd5
"

--- user_files eval: $::certfiles

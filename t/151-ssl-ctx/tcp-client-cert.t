# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;
use Digest::MD5 qw(md5_hex);

repeat_each(2);

plan tests => repeat_each() * (blocks() + 2);

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
--- timeout: 5



=== TEST 2: setsslctx - expecting the two arguments
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
            do
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

                local sock = ngx.socket.tcp()
                sock:settimeout(3000)
                local ok, err = sock:setsslctx(ssl_ctx)
                if not ok then
                    ngx.say("faile to set tcp ssl ctx: ")
                end

                local ok, err = sock:connect("127.0.0.1", 1983)
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, nil, true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))

                local req = "GET /cert HTTP/1.0\r\nHost: server\r\nConnection: close\r\n\r\n"
                local bytes, err = sock:send(req)
                if not bytes then
                    ngx.say("failed to send http request: ", err)
                    return
                end

                ngx.say("sent http request: ", bytes, " bytes.")

                while true do
                    local line, err = sock:receive()
                    if not line then
                        -- ngx.say("failed to receive response status line: ", err)
                        break
                    end

                    ngx.say("received: ", line)
                end

                local ok, err = sock:close()
                ngx.say("close: ", ok, " ", err)
            end  -- do
            collectgarbage()
        }
    }

--- request
GET /t

--- response_body eval
"connected: 1
ssl handshake: userdata
sent http request: 55 bytes.
received: HTTP/1.1 200 OK
received: Server: nginx
received: Content-Type: text/plain
received: Content-Length: 33
received: Connection: close
received: 
received: $::clientCrtMd5
close: 1 nil
"

--- user_files eval: $::certfiles
--- timeout: 5



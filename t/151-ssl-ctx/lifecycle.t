# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;
use Digest::MD5 qw(md5_hex);

repeat_each(2);

plan tests => repeat_each() * (blocks());

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

log_level 'debug';
no_long_string();

run_tests();

__DATA__

=== TEST 1: SSL_CTX * userdata gc
--- config
    location /t {
        content_by_lua_block {
            do
                local ssl_ctx = ngx.ssl.ctx()
                local ok, err = ssl_ctx:init({})
                if not ok then
                    ngx.say("init ssl ctx error: ", err)
                    return
                end
            end
            collectgarbage("collect")
        }
    }

--- request
GET /t

--- ignore_response
--- grep_error_log eval: qr/lua ssl (?:create|free) ctx: [0-9A-F]+:\d+/
--- grep_error_log_out eval
qr/^lua ssl create ctx: ([0-9A-F]+):1
lua ssl free ctx: ([0-9A-F]+):1
$/

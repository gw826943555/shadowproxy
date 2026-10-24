'use strict';
'require view';
'require form';
'require uci';

// Encryption methods accepted by the sslocal build
var methods = [
    "none",
    "table",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "chacha20-ietf",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

return view.extend({
    load: function() {
        return Promise.all([]);
    },

    render: function() {
        var m, s, o;

        m = new form.Map('shadowproxy', _('ShadowProxy'),
            _('ShadowProxy Configuration for tproxy redir and dns'));

        s = m.section(form.GridSection, 'node', _('Nodes'));
        s.anonymous = true;
        s.addremove = true;

        o = s.option(form.Flag, 'enabled', _('Enable'));
        o.editable = true;

        o = s.option(form.Value, 'server', _('Server'),
            _('address of the remote shadowsocks node, IPv4, IPv6 or hostname'));
        o.datatype = 'host';
        o.rmempty = false;

        o = s.option(form.Value, 'server_port', _('Port'));
        o.datatype = 'range(1,65535)';
        o.rmempty = false;

        o = s.option(form.ListValue, 'method', _('Method'));
        methods.forEach(function(m) { o.value(m); });
        o.rmempty = false;

        o = s.option(form.Value, 'password', _('Password'));
        o.password = true;
        o.modalonly = true;

        o = s.option(form.ListValue, 'plugin', _('Plugin'),
            _('Only obfs-local from simple-obfs is supported for now. The plugin program has to be installed on this device. Leave empty to disable.'));
        o.value('', _('none'));
        o.value('obfs-local', 'obfs-local');
        o.rmempty = true;
        o.modalonly = true;

        o = s.option(form.Value, 'plugin_opts', _('Plugin Options'),
            _('simple-obfs options, for example obfs=http;obfs-host=www.bing.com. The obfs value is http or tls.'));
        o.placeholder = 'obfs=http;obfs-host=www.bing.com';
        o.depends('plugin', 'obfs-local');
        o.rmempty = true;
        o.modalonly = true;

        return m.render();
    }
});

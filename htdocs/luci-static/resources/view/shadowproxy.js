'use strict';
'require view';
'require form';
'require fs';
'require rpc';
'require uci';

// Encryption methods accepted by the sslocal build (shadowsocks-rust with the
// default "full" feature set). sslocal refuses to start when it sees an
// unknown method, so this list must only contain methods the binary really
// supports -- check with:
//
//     sslocal --help | grep -A5 'encrypt-method'
//
// Not offered here on purpose:
//   bf-cfb, salsa20        removed upstream, no longer compiled in
//   aes-192-gcm            never existed, upstream only has 128/256 bit GCM
//   xchacha20-ietf-poly1305  needs the non-default aead-cipher-extra feature
//
// The binary supports a few more exotic ones (aes-*-ofb, aes-*-cfb1/cfb8/
// cfb128, camellia-*-ctr/ofb); add them here if they are ever needed.
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
]

var page = view.extend({
    callStatus: rpc.declare({
        object: "service",
        method: "list",
        params: ["name"],
        expect: { "shadowproxy": {} }
    }),

    load: function() {
        return Promise.all([this.callStatus()]);
    },

    render: function (data) {
        var m, s, o;

        m = new form.Map('shadowproxy', _('ShadowProxy'),
            _('ShadowProxy Configuration for tproxy redir and dns'));
        // Render every section as its own tab. The tab id is the UCI section
        // type, so all of them have to be unique.
        m.tabbed = true;

        // Basic network settings (UCI: config conf main)
        s = m.section(form.NamedSection, 'main', "conf", _('Basic Network Settings'));
        s.anonymous = true;

        o = s.option(form.Flag, 'running', _('Enabled'));
        o.cfgvalue = function (section_id) {
            try {
                return data[0]["instances"]["shadowproxy"]["running"];
            } catch (e) {
                return false;
            }
        };
        o.write = function (section_id, formvalue) {
            var value = this.cfgvalue(section_id);
            if (value == formvalue) {
                return
            }
            if (formvalue == false) {
                uci.set("shadowproxy", section_id, "enabled", "0");
            } else {
                uci.set("shadowproxy", section_id, "enabled", "1");
            }

            return uci.set("shadowproxy", section_id, "running", formvalue);
        };
        o.rmempty = false;

        o = s.option(form.Value, 'socks_port', _('Socks Port'),
            _('socks5 proxy local listening port, set 0 to disable it'));
        o.datatype = 'port'
        o.rmempty = false;

        o = s.option(form.Value, 'http_port', _('Http Port'),
            _('http proxy local listening port, set 0 to disable it'));
        o.datatype = 'port'
        o.rmempty = false;

        o = s.option(form.Value, 'redir_port', _('Redir Port'),
            _('redir local listening port'));
        o.datatype = 'port'
        o.rmempty = false;

        o = s.option(form.Value, 'dns_port', _('DNS Port'),
            _('dns local listening port'));
        o.datatype = 'port'
        o.rmempty = false;

        o = s.option(form.Value, 'dns_remote_addr', _('DNS Remote Server'),
            _('dns server used to resolve the proxied domains, the queries go through the tunnel'))
        o.datatype = 'ipaddr';
        o.rmempty = false;

        // Proxy behavior settings (UCI: config settings global)
        s = m.section(form.NamedSection, 'global', "settings", _('Proxy Behavior Settings'));
        s.anonymous = true;

        o = s.option(form.Value, 'worker_count', _('Worker Count'),
            _('thread worker count for processing connections'));
        o.datatype = 'range(1,1024)';
        o.rmempty = false;

        o = s.option(form.Value, 'client_cache_size', _('DNS Client Cache Size'),
            _('should equals the size of max concurrent udp connections'));
        o.datatype = 'range(8,4096)';
        o.rmempty = false;

        o = s.option(form.Flag, 'no_delay', _('TCP No Delay'),
            _('reuse tcp connections or not'));
        o.rmempty = false;

        o = s.option(form.Value, 'keep_alive', _('TCP Keep Alive'),
            _('how many seconds to keep the tcp connection'));
        o.datatype = 'range(5,180)';
        o.rmempty = false;

        o = s.option(form.Flag, 'fast_open', _('TCP Fast Open'),
            _('if platform tcp fast open supported'));
        o.rmempty = false;

        o = s.option(form.Flag, 'mptcp', _('TCP Mptcp'),
            _('if platform tcp mptcp supported'));
        o.rmempty = false;

        o = s.option(form.Value, 'nofile', _('Nofile'),
            _('max allowed sockets limit'));
        o.datatype = 'range(512,20480)';
        o.rmempty = false;

        s = m.section(form.GridSection, 'node', _('Nodes'));
        s.anonymous = true;
        s.addremove = true;

        o = s.option(form.Flag, 'enabled', _('Enable'));
        o.editable = true;

        o = s.option(form.Value, 'server', _('Server'),
            _('address of the remote shadowsocks node, IPv4, IPv6 or hostname'));
        o.datatype = 'host';
        o.rmempty = false;

        // range(1,65535), not 'port': the port datatype also accepts 0, but
        // a server port of 0 makes sslocal reject the whole config.
        o = s.option(form.Value, 'server_port', _('Port'));
        o.datatype = 'range(1,65535)';
        o.rmempty = false;

        o = s.option(form.ListValue, 'method', _('Method'));
        methods.forEach(m => o.value(m));
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

        // The UCI section type doubles as the tab id, so it must differ from
        // the type of the 'main' section above.
        s = m.section(form.NamedSection, 'settings', "rules", _('Rules'),
            _('Proxy domain and bypass rules'));
        s.anonymous = true;
        s.tab('domain', _('Proxy Domain'));
        s.tab('bypass_domain', _('Bypass Domain'));
        s.tab('bypass_ipset', _('Bypass Ipset'));
        s.tab('proxy_ipset', _('Proxy Ipset'));

        var G = 'shadowproxy';
        var GSEC = 'settings';

        // Proxy Domain (stored in UCI section 'config rules')
        o = s.taboption("domain", form.DynamicList, 'proxy_domain', _("Proxy Domain"),
            _("Domains and subdomains resolved through the tunnel."));
        o.rmempty = true;
        o.optional = true;
        o.cfgvalue = function (section_id) {
            var v = uci.get(G, GSEC, 'proxy_domain');
            if (Array.isArray(v)) return v.join('\n');
            return v || '';
        };
        o.write = function (section_id, formvalue) {
            var lines = (formvalue || '').split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
            uci.delete(G, GSEC, 'proxy_domain');
            lines.forEach(function(line) {
                uci.set(G, GSEC, 'proxy_domain', line);
            });
        };

        // Bypass Ipset (stored in UCI section 'config rules')
        o = s.taboption("bypass_ipset", form.DynamicList, 'bypass_ipset', _("Bypass Ipset"),
            _("IP/CIDR ranges bypassing the proxy."));
        o.rmempty = true;
        o.optional = true;
        o.cfgvalue = function (section_id) {
            var v = uci.get(G, GSEC, 'bypass_ipset');
            if (Array.isArray(v)) return v.join('\n');
            return v || '';
        };
        o.write = function (section_id, formvalue) {
            var lines = (formvalue || '').split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
            uci.delete(G, GSEC, 'bypass_ipset');
            lines.forEach(function(line) {
                uci.set(G, GSEC, 'bypass_ipset', line);
            });
        };

        // Proxy Ipset (stored in UCI section 'config rules')
        o = s.taboption("proxy_ipset", form.DynamicList, 'proxy_ipset', _("Proxy Ipset"),
            _("IP/CIDR ranges forced through the proxy tunnel."));
        o.rmempty = true;
        o.optional = true;
        o.cfgvalue = function (section_id) {
            return uci.get(G, GSEC, 'proxy_ipset');
        };
        o.write = function (section_id, formvalue) {
            uci.set(G, GSEC, 'proxy_ipset', formvalue);
        };

        // Bypass Domain (stored in UCI section 'config rules')
        o = s.taboption("bypass_domain", form.DynamicList, 'bypass_domain', _("Bypass Domain"),
            _("Domains and subdomains resolved directly, not through the tunnel."));
        o.rmempty = true;
        o.optional = true;
        o.cfgvalue = function (section_id) {
            var v = uci.get(G, GSEC, 'bypass_domain');
            if (Array.isArray(v)) return v.join('\n');
            return v || '';
        };
        o.write = function (section_id, formvalue) {
            var lines = (formvalue || '').split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
            uci.delete(G, GSEC, 'bypass_domain');
            lines.forEach(function(line) {
                uci.set(G, GSEC, 'bypass_domain', line);
            });
        };

        return m.render();
    }
});

return page;

'use strict';
'require view';
'require form';
'require fs';
'require rpc';
'require uci';

return view.extend({
    callStatus: rpc.declare({
        object: "service",
        method: "list",
        params: ["name"],
        expect: { "shadowsocks-rust": {} }
    }),

    load: function() {
        return Promise.all([this.callStatus()]);
    },

    render: function (data) {
        var m, s, o;

        m = new form.Map('shadowsocks-rust', _('Shadowsocks-Rust'),
            _('Transparent proxy and DNS settings'));

        // Service Settings
        s = m.section(form.NamedSection, 'main', 'conf', _('Service Settings'));
        s.anonymous = true;

        // Runtime status (read-only)
        o = s.option(form.DummyValue, '_running', _('Service Status'));
        o.cfgvalue = function () {
            try {
                return data[0]["instances"]["shadowsocks-rust"]["running"]
                    ? _('Running') : _('Stopped');
            } catch (e) {
                return _('Stopped');
            }
        };

        // Enabled: bound to the UCI 'enabled' option, so saving it always
        // reflects the configured state and always produces a change.
        o = s.option(form.Flag, 'enabled', _('Enabled'),
            _('Allow the service to start. When off, sslocal and the rules are not started.'));
        o.rmempty = false;

        o = s.option(form.Value, 'socks_port', _('SOCKS Port'),
            _('SOCKS5 proxy port, 0 to disable.'));
        o.datatype = 'port';
        o.rmempty = false;

        o = s.option(form.Value, 'http_port', _('HTTP Port'),
            _('HTTP proxy port, 0 to disable.'));
        o.datatype = 'port';
        o.rmempty = false;

        o = s.option(form.Value, 'redir_port', _('TProxy Port'),
            _('Listening port used by the nftables rules.'));
        o.datatype = 'port';
        o.rmempty = false;

        o = s.option(form.Value, 'dns_port', _('DNS Port'),
            _('Local DNS relay port, dnsmasq forwards proxied domains here.'));
        o.datatype = 'port';
        o.rmempty = false;

        o = s.option(form.Value, 'dns_remote_addr', _('DNS Remote Server'),
            _('Upstream DNS for proxied domains, queried through the tunnel.'));
        o.datatype = 'ipaddr';
        o.rmempty = false;

        // Advanced Settings
        s = m.section(form.NamedSection, 'global', 'settings', _('Advanced Settings'));
        s.anonymous = true;

        o = s.option(form.Value, 'worker_count', _('Worker Count'),
            _('Worker threads, set it to the CPU core count.'));
        o.datatype = 'range(1,1024)';
        o.rmempty = false;

        o = s.option(form.Value, 'client_cache_size', _('DNS Client Cache Size'),
            _('Idle upstream DNS connections kept per resolver. Answers are cached by dnsmasq.'));
        o.datatype = 'range(8,4096)';
        o.rmempty = false;

        o = s.option(form.Flag, 'no_delay', _('TCP No Delay'),
            _('Disable Nagle for lower latency at the cost of more packets.'));
        o.rmempty = false;

        o = s.option(form.Value, 'keep_alive', _('TCP Keep Alive'),
            _('Keepalive probe interval in seconds, used to drop dead connections.'));
        o.datatype = 'range(5,180)';
        o.rmempty = false;

        o = s.option(form.Flag, 'fast_open', _('TCP Fast Open'),
            _('Requires kernel and server support.'));
        o.rmempty = false;

        o = s.option(form.Flag, 'mptcp', _('TCP MPTCP'),
            _('Requires kernel, server and multiple paths.'));
        o.rmempty = false;

        o = s.option(form.Value, 'nofile', _('Open File Limit'),
            _('Each proxied connection uses two descriptors.'));
        o.datatype = 'range(512,20480)';
        o.rmempty = false;

        o = s.option(form.ListValue, 'log_level', _('Log Level'),
            _('Log verbosity written to syslog.'));
        o.value('info', _('Info'));
        o.value('debug', _('Debug'));
        o.value('trace', _('Trace'));
        o.default = 'info';
        o.rmempty = false;

        return m.render();
    }
});

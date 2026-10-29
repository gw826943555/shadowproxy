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
            _('Shadowsocks-Rust Configuration for tproxy redir and dns'));

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
        o = s.option(form.Flag, 'enabled', _('Enabled'));
        o.rmempty = false;

        o = s.option(form.Value, 'socks_port', _('Socks Port'),
            _('socks5 proxy local listening port, set 0 to disable it'));
        o.datatype = 'port';
        o.rmempty = false;

        o = s.option(form.Value, 'http_port', _('Http Port'),
            _('http proxy local listening port, set 0 to disable it'));
        o.datatype = 'port';
        o.rmempty = false;

        o = s.option(form.Value, 'redir_port', _('Redir Port'),
            _('redir local listening port'));
        o.datatype = 'port';
        o.rmempty = false;

        o = s.option(form.Value, 'dns_port', _('DNS Port'),
            _('dns local listening port'));
        o.datatype = 'port';
        o.rmempty = false;

        o = s.option(form.Value, 'dns_remote_addr', _('DNS Remote Server'),
            _('dns server used to resolve the proxied domains, the queries go through the tunnel'));
        o.datatype = 'ipaddr';
        o.rmempty = false;

        // Advanced Settings
        s = m.section(form.NamedSection, 'global', 'settings', _('Advanced Settings'));
        s.anonymous = true;

        o = s.option(form.Value, 'worker_count', _('Worker Count'),
            _('thread worker count for processing connections'));
        o.datatype = 'range(1,1024)';
        o.rmempty = false;

        o = s.option(form.Value, 'client_cache_size', _('DNS Client Cache Size'),
            _('Idle upstream DNS connections kept for each resolver. Higher values avoid reconnecting for repeated queries, the DNS answers themselves are cached by dnsmasq.'));
        o.datatype = 'range(8,4096)';
        o.rmempty = false;

        o = s.option(form.Flag, 'no_delay', _('TCP No Delay'),
            _('Disable the Nagle algorithm so small packets are sent immediately. Lower latency at the cost of slightly more packets.'));
        o.rmempty = false;

        o = s.option(form.Value, 'keep_alive', _('TCP Keep Alive'),
            _('Seconds between TCP keepalive probes, used to detect and drop dead connections.'));
        o.datatype = 'range(5,180)';
        o.rmempty = false;

        o = s.option(form.Flag, 'fast_open', _('TCP Fast Open'),
            _('if platform tcp fast open supported'));
        o.rmempty = false;

        o = s.option(form.Flag, 'mptcp', _('TCP Mptcp'),
            _('if platform tcp mptcp supported'));
        o.rmempty = false;

        o = s.option(form.Value, 'nofile', _('Nofile'),
            _('File descriptor limit for the sslocal process. Each proxied connection uses one descriptor for the client side and one for the server side, the supervisor caps the limit at 20480.'));
        o.datatype = 'range(512,20480)';
        o.rmempty = false;

        o = s.option(form.ListValue, 'log_level', _('Log Level'),
            _('Verbosity of sslocal logs, written to the system log'));
        o.value('info', _('Info'));
        o.value('debug', _('Debug'));
        o.value('trace', _('Trace'));
        o.default = 'info';
        o.rmempty = false;

        return m.render();
    }
});

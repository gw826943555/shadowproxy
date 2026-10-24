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
        expect: { "shadowproxy": {} }
    }),

    load: function() {
        return Promise.all([this.callStatus()]);
    },

    render: function (data) {
        var m, s, o;

        m = new form.Map('shadowproxy', _('ShadowProxy'),
            _('ShadowProxy Configuration for tproxy redir and dns'));

        // Service Settings
        s = m.section(form.NamedSection, 'main', 'conf', _('Service Settings'));
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
                return;
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

        return m.render();
    }
});

'use strict';
'require view';
'require form';
'require uci';

return view.extend({
    load: function() {
        return Promise.all([]);
    },

    render: function() {
        var m, s, o;

        m = new form.Map('shadowproxy', _('ShadowProxy'),
            _('ShadowProxy Configuration for tproxy redir and dns'));

        s = m.section(form.NamedSection, 'settings', 'rules', _('Rules'),
            _('Proxy domain and bypass rules'));
        s.anonymous = true;
        s.tab('domain', _('Proxy Domain'));
        s.tab('bypass_domain', _('Bypass Domain'));
        s.tab('bypass_ipset', _('Bypass Ipset'));
        s.tab('proxy_ipset', _('Proxy Ipset'));

        var G = 'shadowproxy';
        var GSEC = 'settings';

        o = s.taboption('domain', form.DynamicList, 'proxy_domain', _('Proxy Domain'),
            _('Domains and subdomains resolved through the tunnel.'));
        o.rmempty = true;
        o.optional = true;
        o.cfgvalue = function(section_id) {
            var v = uci.get(G, GSEC, 'proxy_domain');
            if (Array.isArray(v)) return v.join('\n');
            return v || '';
        };
        o.write = function(section_id, formvalue) {
            var lines = (formvalue || '').split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
            uci.delete(G, GSEC, 'proxy_domain');
            lines.forEach(function(line) {
                uci.set(G, GSEC, 'proxy_domain', line);
            });
        };

        o = s.taboption('bypass_domain', form.DynamicList, 'bypass_domain', _('Bypass Domain'),
            _('Domains and subdomains resolved directly, not through the tunnel.'));
        o.rmempty = true;
        o.optional = true;
        o.cfgvalue = function(section_id) {
            var v = uci.get(G, GSEC, 'bypass_domain');
            if (Array.isArray(v)) return v.join('\n');
            return v || '';
        };
        o.write = function(section_id, formvalue) {
            var lines = (formvalue || '').split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
            uci.delete(G, GSEC, 'bypass_domain');
            lines.forEach(function(line) {
                uci.set(G, GSEC, 'bypass_domain', line);
            });
        };

        o = s.taboption('bypass_ipset', form.DynamicList, 'bypass_ipset', _('Bypass Ipset'),
            _('IP/CIDR ranges bypassing the proxy.'));
        o.rmempty = true;
        o.optional = true;
        o.cfgvalue = function(section_id) {
            var v = uci.get(G, GSEC, 'bypass_ipset');
            if (Array.isArray(v)) return v.join('\n');
            return v || '';
        };
        o.write = function(section_id, formvalue) {
            var lines = (formvalue || '').split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
            uci.delete(G, GSEC, 'bypass_ipset');
            lines.forEach(function(line) {
                uci.set(G, GSEC, 'bypass_ipset', line);
            });
        };

        o = s.taboption('proxy_ipset', form.DynamicList, 'proxy_ipset', _('Proxy Ipset'),
            _('IP/CIDR ranges forced through the proxy tunnel.'));
        o.rmempty = true;
        o.optional = true;
        o.cfgvalue = function(section_id) {
            var v = uci.get(G, GSEC, 'proxy_ipset');
            if (Array.isArray(v)) return v.join('\n');
            return v || '';
        };
        o.write = function(section_id, formvalue) {
            var lines = (formvalue || '').split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
            uci.delete(G, GSEC, 'proxy_ipset');
            lines.forEach(function(line) {
                uci.set(G, GSEC, 'proxy_ipset', line);
            });
        };

        return m.render();
    }
});

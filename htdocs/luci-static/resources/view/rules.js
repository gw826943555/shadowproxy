'use strict';
'require view';
'require form';

return view.extend({
    load: function() {
        return Promise.all([]);
    },

    render: function() {
        var m, s, o;

        m = new form.Map('shadowproxy', _('ShadowProxy'),
            _('ShadowProxy Configuration for tproxy redir and dns'));

        s = m.section(form.NamedSection, 'settings', 'rules', _('Rules'),
            _('Proxy domain, IP and source rules'));
        s.anonymous = true;
        s.tab('policy', _('Policy'));
        s.tab('src_bypass', _('Source Bypass'));
        s.tab('src_forward', _('Source Forward'));
        s.tab('src_checkdst', _('Source Check Destination'));
        s.tab('domain', _('Proxy Domain'));
        s.tab('bypass_domain', _('Bypass Domain'));
        s.tab('bypass_ipset', _('Bypass Ipset'));
        s.tab('proxy_ipset', _('Proxy Ipset'));

        o = s.taboption('policy', form.ListValue, 'src_default', _('Default for Source IPs'),
            _('Used for clients not listed in the source tabs.'));
        o.value('accept', _('Direct'));
        o.value('checkdst', _('Check Destination'));
        o.value('forward', _('Proxy All'));
        o.default = 'accept';
        o.rmempty = false;

        o = s.taboption('policy', form.ListValue, 'dst_default', _('Default for Destinations'),
            _('Used for destinations not listed in the destination tabs.'));
        o.value('accept', _('Direct'));
        o.value('forward', _('Proxy'));
        o.default = 'accept';
        o.rmempty = false;

        o = s.taboption('policy', form.ListValue, 'local_default', _('Router Traffic'),
            _('Policy for connections made by the router itself.'));
        o.value('none', _('Direct'));
        o.value('checkdst', _('Check Destination'));
        o.value('forward', _('Proxy All'));
        o.default = 'none';
        o.rmempty = false;

        o = s.taboption('src_bypass', form.DynamicList, 'src_bypass', _('Source Bypass'),
            _('Client IP/CIDR always connecting directly.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('src_forward', form.DynamicList, 'src_forward', _('Source Forward'),
            _('Client IP/CIDR always proxied.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('src_checkdst', form.DynamicList, 'src_checkdst', _('Source Check Destination'),
            _('Client IP/CIDR whose destinations are matched against the lists below.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('domain', form.DynamicList, 'proxy_domain', _('Proxy Domain'),
            _('Domains and subdomains resolved through the tunnel.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('bypass_domain', form.DynamicList, 'bypass_domain', _('Bypass Domain'),
            _('Domains and subdomains resolved directly, not through the tunnel.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('bypass_ipset', form.DynamicList, 'bypass_ipset', _('Bypass Ipset'),
            _('IP/CIDR ranges bypassing the proxy.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('proxy_ipset', form.DynamicList, 'proxy_ipset', _('Proxy Ipset'),
            _('IP/CIDR ranges forced through the proxy tunnel.'));
        o.rmempty = true;
        o.optional = true;

        return m.render();
    }
});

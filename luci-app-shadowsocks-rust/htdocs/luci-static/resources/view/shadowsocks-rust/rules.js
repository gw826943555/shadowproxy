'use strict';
'require view';
'require form';
'require uci';

return view.extend({
    load: function() {
        return Promise.all([
            uci.load('shadowsocks-rust')
        ]);
    },

    render: function() {
        var m, s, o;

        m = new form.Map('shadowsocks-rust', _('Shadowsocks-Rust'),
            _('Transparent proxy and DNS settings'));

        s = m.section(form.NamedSection, 'settings', 'rules', _('Rules'),
            _('Policy, source and destination rules'));
        s.anonymous = true;
        s.tab('policy', _('Policy'));
        s.tab('sources', _('Source Rules'));
        s.tab('destinations', _('Destination Rules'));

        o = s.taboption('policy', form.Flag, 'enabled', _('Apply TProxy Rules'),
            _('Install the route, nftables and dnsmasq rules. Off starts sslocal only.'));
        o.rmempty = false;

        o = s.taboption('policy', form.Flag, 'dns_hijack', _('Hijack LAN DNS'),
            _('Redirect DNS queries from LAN clients here, so they follow the domain rules.'));
        o.default = o.enabled;
        o.rmempty = false;

        var dns_port = uci.get('shadowsocks-rust', 'main', 'dns_port') || '5300';
        var local_relay = '127.0.0.1:' + dns_port;

        o = s.taboption('policy', form.Value, 'proxy_domain_dns', _('Proxy Domain DNS'),
            _('Resolver used for the proxy domains. Leave empty for the system resolvers, or enter an ip:port.'));
        o.value(local_relay, _('Local Relay') + ' (' + local_relay + ')');
        o.datatype = 'ipaddrport(1)';
        o.placeholder = _('System DNS');
        o.rmempty = true;

        o = s.taboption('policy', form.Value, 'bypass_domain_dns', _('Bypass Domain DNS'),
            _('Resolver used for the bypass domains. Leave empty for the system resolvers, or enter an ip:port.'));
        o.value(local_relay, _('Local Relay') + ' (' + local_relay + ')');
        o.datatype = 'ipaddrport(1)';
        o.placeholder = _('System DNS');
        o.rmempty = true;

        o = s.taboption('policy', form.Value, 'other_domain_dns', _('Other Domains DNS'),
            _('Resolver for the domains not matched by the lists. When set it replaces the system DNS, leave empty to use the system resolvers.'));
        o.value(local_relay, _('Local Relay') + ' (' + local_relay + ')');
        o.datatype = 'ipaddrport(1)';
        o.placeholder = _('System DNS');
        o.rmempty = true;

        o = s.taboption('policy', form.ListValue, 'src_default', _('Default for Source IPs'),
            _('For clients not listed in the source tabs.'));
        o.value('accept', _('Direct'));
        o.value('checkdst', _('Check Destination'));
        o.value('forward', _('Proxy All'));
        o.default = 'accept';
        o.rmempty = false;

        o = s.taboption('policy', form.ListValue, 'dst_default', _('Default for Destinations'),
            _('For destinations not matched by the domain and IP lists.'));
        o.value('accept', _('Direct'));
        o.value('forward', _('Proxy'));
        o.default = 'accept';
        o.rmempty = false;

        o = s.taboption('policy', form.ListValue, 'local_default', _('Router Traffic'),
            _('For connections made by the router itself.'));
        o.value('none', _('Direct'));
        o.value('checkdst', _('Check Destination'));
        o.value('forward', _('Proxy All'));
        o.default = 'none';
        o.rmempty = false;

        o = s.taboption('policy', form.Value, 'refresh_hours', _('Lists Refresh Interval'),
            _('Hours between two downloads of the remote lists, 0 only once at start.'));
        o.datatype = 'range(0,8760)';
        o.default = '24';
        o.placeholder = '24';
        o.rmempty = false;

        o = s.taboption('sources', form.DynamicList, 'src_bypass', _('Source Bypass'),
            _('Client IP/CIDR always direct.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('sources', form.DynamicList, 'src_forward', _('Source Forward'),
            _('Client IP/CIDR always proxied.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('sources', form.DynamicList, 'src_checkdst', _('Source Check Destination'),
            _('Client IP/CIDR matched against the destination lists.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('destinations', form.DynamicList, 'proxy_domain', _('Proxy Domain'),
            _('Domains and subdomains whose traffic goes through the tunnel.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('destinations', form.DynamicList, 'proxy_domain_url', _('Proxy Domain URL'),
            _('Text files with one domain per line, added to the list above.'));
        o.placeholder = 'https://example.com/proxy-domains.txt';
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('destinations', form.DynamicList, 'proxy_ipset', _('Proxy IP Set'),
            _('IP/CIDR ranges always proxied.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('destinations', form.DynamicList, 'proxy_ipset_url', _('Proxy IP Set URL'),
            _('Text files with one IP or CIDR per line (# comments allowed), added to the list above.'));
        o.placeholder = 'https://example.com/proxy-ips.txt';
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('destinations', form.DynamicList, 'bypass_domain', _('Bypass Domain'),
            _('Domains and subdomains resolved directly.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('destinations', form.DynamicList, 'bypass_domain_url', _('Bypass Domain URL'),
            _('Text files with one domain per line, added to the list above.'));
        o.placeholder = 'https://example.com/bypass-domains.txt';
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('destinations', form.DynamicList, 'bypass_ipset', _('Bypass IP Set'),
            _('IP/CIDR ranges always direct.'));
        o.rmempty = true;
        o.optional = true;

        o = s.taboption('destinations', form.DynamicList, 'bypass_ipset_url', _('Bypass IP Set URL'),
            _('Text files with one IP or CIDR per line (# comments allowed), added to the list above.'));
        o.placeholder = 'https://example.com/bypass-ips.txt';
        o.rmempty = true;
        o.optional = true;

        return m.render();
    }
});

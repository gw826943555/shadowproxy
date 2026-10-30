'use strict';
'require view';
'require form';
'require uci';
'require ui';

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
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/* ------------------------------------------------------------------ */
/* SIP002 parsing                                                      */
/* ------------------------------------------------------------------ */

function safeDecode(s) {
    try {
        return decodeURIComponent(s);
    } catch (e) {
        return s;
    }
}

/* Decode standard or URL-safe base64 into an UTF-8 string, null on error. */
function b64decode(s) {
    var str = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');

    while (str.length % 4)
        str += '=';

    var bin;

    try {
        bin = atob(str);
    } catch (e) {
        return null;
    }

    try {
        return new TextDecoder('utf-8').decode(Uint8Array.from(bin, function(c) {
            return c.charCodeAt(0);
        }));
    } catch (e) {
        return bin;
    }
}

/* Split "host:port", "[v6]:port", never throws. */
function splitHostPort(s) {
    var host, port;

    if (s.charAt(0) == '[') {
        var end = s.indexOf(']');

        if (end < 0)
            return null;

        host = s.slice(1, end);

        if (s.charAt(end + 1) != ':')
            return null;

        port = s.slice(end + 2);
    } else {
        var colon = s.lastIndexOf(':');

        if (colon < 0)
            return null;

        host = s.slice(0, colon);
        port = s.slice(colon + 1);

        // An IPv6 address must be wrapped in brackets to be unambiguous.
        if (host.indexOf(':') >= 0)
            return null;
    }

    if (!host || !/^[0-9]+$/.test(port))
        return null;

    var num = +port;

    if (num < 1 || num > 65535)
        return null;

    return [ host, port ];
}

/* Parse a SIP002 ss:// URI. Both the userinfo form
 *
 *   ss://base64(method:password)@host:port/?plugin=...#tag
 *
 * and the legacy form
 *
 *   ss://base64(method:password@host:port)#tag
 *
 * are accepted. Throws an Error with a translated message on bad input. */
function parseSSUri(uri) {
    var s = uri.replace(/^ss:\/\//i, '');
    var name = '';
    var query = '';
    var hash = s.indexOf('#');

    if (hash >= 0) {
        name = safeDecode(s.slice(hash + 1)).trim();
        s = s.slice(0, hash);
    }

    var qmark = s.indexOf('?');

    if (qmark >= 0) {
        query = s.slice(qmark + 1);
        s = s.slice(0, qmark);
    }

    var method, password, hostport;
    var at = s.lastIndexOf('@');

    if (at >= 0) {
        // SIP002: the userinfo is base64 of "method:password". A few
        // clients emit it unencoded, accept that as a fallback.
        var userinfo = safeDecode(s.slice(0, at));
        var decoded = b64decode(userinfo);

        if (!decoded || decoded.indexOf(':') < 0)
            decoded = userinfo;

        var colon = decoded.indexOf(':');

        if (colon < 0)
            throw new Error(_('missing method or password'));

        method = decoded.slice(0, colon);
        password = decoded.slice(colon + 1);
        hostport = s.slice(at + 1).replace(/\/+$/, '');
    } else {
        // Legacy form: the whole payload is base64.
        var legacy = b64decode(s);

        if (!legacy)
            throw new Error(_('invalid base64 payload'));

        var lat = legacy.lastIndexOf('@');

        if (lat < 0)
            throw new Error(_('missing host'));

        var ui = legacy.slice(0, lat);
        var lcolon = ui.indexOf(':');

        if (lcolon < 0)
            throw new Error(_('missing method or password'));

        method = ui.slice(0, lcolon);
        password = ui.slice(lcolon + 1);
        hostport = legacy.slice(lat + 1);
    }

    if (!method)
        throw new Error(_('missing method'));

    var hp = splitHostPort(hostport);

    if (!hp)
        throw new Error(_('invalid host or port'));

    var node = {
        name: name,
        server: hp[0],
        server_port: hp[1],
        method: method,
        password: password,
        plugin: '',
        plugin_opts: '',
        unsupported_plugin: ''
    };

    // SIP002 query parameters, only "plugin" is relevant for sslocal.
    query.split('&').forEach(function(pair) {
        if (!pair)
            return;

        var eq = pair.indexOf('=');
        var key = safeDecode(eq < 0 ? pair : pair.slice(0, eq));
        var val = eq < 0 ? '' : safeDecode(pair.slice(eq + 1));

        if (key != 'plugin' || !val)
            return;

        var parts = val.split(';');
        var pname = parts.shift();

        if (pname == 'obfs-local' || pname == 'simple-obfs') {
            node.plugin = 'obfs-local';
            node.plugin_opts = parts.join(';');
        } else {
            node.unsupported_plugin = pname;
        }
    });

    return node;
}

/* ------------------------------------------------------------------ */
/* view                                                                */
/* ------------------------------------------------------------------ */

return view.extend({
    load: function() {
        return Promise.all([]);
    },

    addNode: function(node) {
        var sid = uci.add('shadowsocks-rust', 'node');

        uci.set('shadowsocks-rust', sid, 'enabled', '1');
        uci.set('shadowsocks-rust', sid, 'server', node.server);
        uci.set('shadowsocks-rust', sid, 'server_port', String(node.server_port));
        uci.set('shadowsocks-rust', sid, 'method', node.method);
        uci.set('shadowsocks-rust', sid, 'password', node.password);

        if (node.name)
            uci.set('shadowsocks-rust', sid, 'name', node.name);

        if (node.plugin) {
            uci.set('shadowsocks-rust', sid, 'plugin', node.plugin);

            if (node.plugin_opts)
                uci.set('shadowsocks-rust', sid, 'plugin_opts', node.plugin_opts);
        }
    },

    importNodes: function(text) {
        var existing = { };
        var errors = [ ];
        var imported = 0;
        var skipped = 0;
        var unknown = { };

        uci.sections('shadowsocks-rust', 'node').forEach(function(s) {
            if (s.server && s.server_port)
                existing[s.server + ':' + s.server_port] = true;
        });

        text.split(/\r?\n/).forEach(function(line, idx) {
            line = line.trim();

            if (!line || line.charAt(0) == '#')
                return;

            if (!/^ss:\/\//i.test(line)) {
                errors.push(_('Line %d: not an ss:// URI').format(idx + 1));
                return;
            }

            var node;

            try {
                node = parseSSUri(line);
            } catch (e) {
                errors.push(_('Line %d: %s').format(idx + 1, e.message));
                return;
            }

            var key = node.server + ':' + node.server_port;

            if (existing[key]) {
                skipped++;
                return;
            }

            if (node.unsupported_plugin)
                unknown[node.unsupported_plugin] = true;

            if (methods.indexOf(node.method) < 0)
                unknown[node.method] = true;

            this.addNode(node);
            existing[key] = true;
            imported++;
        }, this);

        var summary = _('Imported %d node(s), skipped %d duplicate(s).')
            .format(imported, skipped);

        if (Object.keys(unknown).length)
            summary += ' ' + _('Unsupported method or plugin, imported unchanged: %s')
                .format(Object.keys(unknown).join(', '));

        if (!imported) {
            this.showImportResult(summary, errors, false);
            return;
        }

        return uci.save().then(function() {
            return uci.apply();
        }).then(function() {
            this.showImportResult(summary, errors, true);
        }.bind(this)).catch(function(err) {
            this.showImportResult(_('Failed to save the imported nodes: %s').format(err), errors, false);
        }.bind(this));
    },

    showImportResult: function(summary, errors, reload) {
        ui.showModal(_('Import result'), [
            E('p', {}, summary),
            errors.length ? E('ul', { 'style': 'max-height:40vh;overflow:auto' },
                errors.map(function(e) { return E('li', {}, e); })) : '',
            E('div', { 'class': 'right' }, [
                E('button', {
                    'class': 'cbi-button cbi-button-apply',
                    'click': function() {
                        if (reload)
                            location.reload();
                        else
                            ui.hideModal();
                    }
                }, _('OK'))
            ])
        ]);
    },

    showImportDialog: function() {
        var self = this;
        var input = E('textarea', {
            'id': 'ss-uri-import',
            'class': 'cbi-input-text',
            'rows': 6,
            'style': 'width:100%;font-family:monospace',
            'placeholder': 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#node1'
        });

        ui.showModal(_('Import nodes'), [
            E('p', { 'class': 'cbi-section-descr' },
                _('Paste one ss:// URI per line. SIP002 and the legacy form are supported, imported nodes are enabled immediately.')),
            E('div', { 'class': 'cbi-value' }, [
                E('div', { 'class': 'cbi-value-field' }, input)
            ]),
            E('div', { 'class': 'right' }, [
                E('button', {
                    'class': 'cbi-button',
                    'click': function() { ui.hideModal(); }
                }, _('Cancel')),
                ' ',
                E('button', {
                    'class': 'cbi-button cbi-button-action',
                    'click': function(ev) {
                        ev.preventDefault();
                        self.importNodes(input.value);
                    }
                }, _('Import'))
            ])
        ]);
    },

    render: function() {
        var m, s, o;

        m = new form.Map('shadowsocks-rust', _('Shadowsocks-Rust'),
            _('Transparent proxy and DNS settings'));

        s = m.section(form.GridSection, 'node', _('Nodes'));
        s.anonymous = true;
        s.addremove = true;

        o = s.option(form.Flag, 'enabled', _('Enabled'));
        o.editable = true;

        o = s.option(form.Value, 'name', _('Name'),
            _('Optional label, taken from the #tag on import.'));
        o.rmempty = true;

        o = s.option(form.Value, 'server', _('Server'),
            _('Remote server address: IPv4, IPv6 or hostname.'));
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
            _('Only obfs-local (simple-obfs) is supported. The binary must be installed, otherwise sslocal fails to start.'));
        o.value('', _('none'));
        o.value('obfs-local', 'obfs-local');
        o.rmempty = true;
        o.modalonly = true;

        o = s.option(form.Value, 'plugin_opts', _('Plugin Options'),
            _('simple-obfs options, e.g. obfs=http;obfs-host=www.bing.com (obfs is http or tls).'));
        o.placeholder = 'obfs=http;obfs-host=www.bing.com';
        o.depends('plugin', 'obfs-local');
        o.rmempty = true;
        o.modalonly = true;

        return m.render().then(function(mapNode) {
            var createEl = mapNode.querySelector('.cbi-tblsection-create');

            if (createEl) {
                createEl.appendChild(E('button', {
                    'class': 'cbi-button',
                    'click': function(ev) {
                        ev.preventDefault();
                        this.showImportDialog();
                    }.bind(this)
                }, _('Import')));
            }

            return mapNode;
        }.bind(this));
    }
});

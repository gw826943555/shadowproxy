#!/usr/bin/ucode
'use strict';

/*
 * Remote list handling and dnsmasq rules for shadowsocks-rust.
 *
 *   render   regenerate the rules file in the dnsmasq conf-dir from the
 *            local UCI lists and the cached domain lists (no network access)
 *   refresh  download the remote domain and IP lists, update the caches,
 *            regenerate the dnsmasq rules and, when the IP lists changed,
 *            reload the nftables ruleset (meant to run as a procd instance)
 *   remove   drop the rules file from the dnsmasq conf-dir
 *
 * Downloaded IP lists are cached for rules.uc, which merges them into the
 * nft sets. The dnsmasq rules live in the tmpfs conf-dir, so the overlay
 * filesystem is never written and a stale file disappears on reboot.
 */

let fs = require('fs');
let uci = require('uci');

const NAME = 'shadowsocks-rust';
const CACHE_DIR = '/var/shadowsocks-rust';
const PROXY_CACHE = CACHE_DIR + '/proxy-domains.cache';
const BYPASS_CACHE = CACHE_DIR + '/bypass-domains.cache';
const PROXY_IP_CACHE = CACHE_DIR + '/proxy-ips.cache';
const BYPASS_IP_CACHE = CACHE_DIR + '/bypass-ips.cache';
const RULES_UC = '/usr/share/shadowsocks-rust/ss-rules/rules.uc';
const RULES_FILE = 'shadowsocks-rust.conf';
const NFT_TABLE = 'shadowsocks-rust-mangle';
const DNS_PORT_DEFAULT = 5300;
const DOMAIN_RE = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
const URL_RE = /^https?:\/\/[^[:space:]'"]+$/;

let ctx = uci.cursor();

/* ------------------------------------------------------------------ */
/* logging                                                             */

function info(msg) {
	let p = fs.popen([ 'logger', '-p', '6', '-t', NAME ], 'w');

	if (p) {
		p.write(msg + '\n');
		p.close();
	}
}

function error(msg) {
	let p = fs.popen([ 'logger', '-p', '3', '-t', NAME ], 'w');

	if (p) {
		p.write(msg + '\n');
		p.close();
	}
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */

function uci_list(section, option) {
	let v = ctx.get(NAME, section, option);

	if (v == null)
		return [];

	return type(v) == 'array' ? v : split(v, /[ \t\n]+/);
}

/* Create /var/shadowsocks-rust, ignoring an already existing directory.
 * fs.mkdir() returns null instead of throwing on error. */
function ensure_cache_dir() {
	fs.mkdir(CACHE_DIR);
}

/* Download one URL and return its content, null on failure. */
function fetch(url) {
	let p = fs.popen([ 'uclient-fetch', '-q', '-T', '15', '-O', '-', url ], 'r');

	if (!p)
		return null;

	let data = p.read('all');
	p.close();
	return data;
}

/* Trim, strip comments, validate and de-duplicate a domain list. Invalid
 * entries are counted and reported once, a large list with a few bad lines
 * must not flood syslog. */
function normalize(text) {
	let seen = {};
	let out = [];
	let invalid = 0;
	let sample = null;

	if (!text)
		return out;

	for (let line in split(text, '\n')) {
		line = trim(replace(line, /#.*$/, ''));

		if (!line)
			continue;

		if (!match(line, DOMAIN_RE)) {
			invalid++;
			sample ??= line;
			continue;
		}

		if (line in seen)
			continue;

		seen[line] = true;
		push(out, line);
	}

	if (invalid)
		error(sprintf('%d invalid domain entries skipped (e.g. "%s")', invalid, sample));

	return out;
}

/* Remove from the proxy list every domain equal to or a subdomain of an
 * entry in the bypass list. */
function filter_proxy(proxy, bypass) {
	let set = {};
	let out = [];

	for (let b in bypass)
		set[b] = true;

	for (let d in proxy) {
		if (set[d])
			continue;

		let labels = split(d, '.');
		let n = length(labels);
		let suffix = labels[n - 1];
		let hit = set[suffix];

		for (let i = n - 2; i >= 0 && !hit; i--) {
			suffix = labels[i] + '.' + suffix;
			hit = set[suffix];
		}

		if (!hit)
			push(out, d);
	}

	return out;
}

/* Local UCI list plus the cached remote list, normalized. */
function load_domains(option, cache_file) {
	let lines = [];

	for (let d in uci_list('settings', option))
		push(lines, d);

	let cached = fs.readfile(cache_file);

	if (cached)
		for (let l in split(cached, '\n'))
			push(lines, l);

	return normalize(join('\n', lines));
}

/* ------------------------------------------------------------------ */
/* IP lists                                                            */

/* Number with an upper bound, rejects leading zeros and other junk. */
function is_num(s, max) {
	if (!match(s, /^(0|[1-9][0-9]*)$/))
		return false;

	let n = int(s);

	return n >= 0 && n <= max;
}

function valid_v4(s) {
	let p = split(s, '/');

	if (length(p) > 2)
		return false;

	let o = split(p[0], '.');

	if (length(o) != 4)
		return false;

	for (let x in o)
		if (!is_num(x, 255))
			return false;

	return length(p) == 2 ? is_num(p[1], 32) : true;
}

function valid_v6(s) {
	let p = split(s, '/');

	if (length(p) > 2)
		return false;

	let a = p[0];

	if (!match(a, /^[0-9A-Fa-f:]+$/) || index(a, ':') < 0)
		return false;

	if (index(a, ':::') >= 0)
		return false;

	let dbl = index(a, '::') >= 0;

	if (dbl) {
		if (index(substr(a, index(a, '::') + 2), '::') >= 0)
			return false;

		if (substr(a, 0, 1) == ':' && substr(a, 1, 1) != ':')
			return false;

		if (substr(a, length(a) - 1) == ':' && substr(a, length(a) - 2, 1) != ':')
			return false;
	}
	else if (substr(a, 0, 1) == ':' || substr(a, length(a) - 1) == ':') {
		return false;
	}

	let count = 0;

	for (let g in split(a, ':')) {
		if (!g)
			continue;

		if (length(g) > 4)
			return false;

		count++;
	}

	if (dbl ? count > 7 : count != 8)
		return false;

	return length(p) == 2 ? is_num(p[1], 128) : true;
}

function valid_ip(s) {
	return index(s, ':') >= 0 ? valid_v6(s) : valid_v4(s);
}

/* Trim, strip comments, validate and de-duplicate an IP list. */
function normalize_ips(text) {
	let seen = {};
	let out = [];
	let invalid = 0;
	let sample = null;

	if (!text)
		return out;

	for (let line in split(text, '\n')) {
		line = trim(replace(line, /#.*$/, ''));

		if (!line)
			continue;

		if (!valid_ip(line)) {
			invalid++;
			sample ??= line;
			continue;
		}

		if (line in seen)
			continue;

		seen[line] = true;
		push(out, line);
	}

	if (invalid)
		error(sprintf('%d invalid IP entries skipped (e.g. "%s")', invalid, sample));

	return out;
}

function refresh_ip_one(option, cache_file) {
	let urls = uci_list('settings', option);
	let old = fs.readfile(cache_file);

	ensure_cache_dir();

	/* No URL configured: drop the cache so stale entries disappear. */
	if (!length(urls)) {
		fs.unlink(cache_file);
		return old != null;
	}

	let data = '';

	for (let url in urls) {
		if (!match(url, URL_RE)) {
			error(sprintf('invalid IP list URL "%s", skipped', url));
			continue;
		}

		let content = fetch(url);

		if (content) {
			data += content;

			if (!match(content, /\n$/))
				data += '\n';
		}
		else {
			error(sprintf('failed to download IP list "%s"', url));
		}
	}

	let list = normalize_ips(data);

	if (!length(list)) {
		info('IP list is empty, keeping the cached list');
		return false;
	}

	let text = join('\n', list) + '\n';

	if (text == old)
		return false;

	let tmp = sprintf('%s.%d.tmp', cache_file, clock()[1]);

	if (fs.writefile(tmp, text) && fs.rename(tmp, cache_file)) {
		info(sprintf('updated cache %s (%d IPs)', cache_file, length(list)));
		return true;
	}

	fs.unlink(tmp);
	error(sprintf('failed to write %s', cache_file));

	return false;
}

function refresh_ip_cache() {
	let bypass = refresh_ip_one('bypass_ipset_url', BYPASS_IP_CACHE);
	let forward = refresh_ip_one('proxy_ipset_url', PROXY_IP_CACHE);

	return bypass || forward;
}

/* Re-render the nftables ruleset and replace the table in one transaction.
 * Used when a downloaded IP list changes, the chains themselves are only
 * re-created by the init script. */
function reload_nft() {
	let r = fs.popen([ 'ucode', '-T', RULES_UC ], 'r');

	if (!r)
		return false;

	let ruleset = r.read('all');
	r.close();

	if (!ruleset || index(ruleset, 'table inet ' + NFT_TABLE) < 0) {
		error('failed to render the nftables ruleset');
		return false;
	}

	let p = fs.popen([ 'nft', '-f', '-' ], 'w');

	if (!p)
		return false;

	p.write('delete table inet ' + NFT_TABLE + '\n');
	p.write(ruleset);
	p.close();

	info('nftables ruleset updated with the new IP list');

	return true;
}

/* ------------------------------------------------------------------ */
/* dnsmasq config                                                      */

/* Directory dnsmasq includes as --conf-dir, using the same logic as
 * /etc/init.d/dnsmasq: the confdir option of the first dnsmasq instance or
 * /tmp/dnsmasq.<section>.d when it is not set. Keeping the rules in tmpfs
 * avoids rewriting the flash on every start. */
function dnsmasq_confdir() {
	let sec = ctx.get_first('dhcp', 'dnsmasq');

	if (!sec)
		return '/tmp/dnsmasq.d';

	let dir = ctx.get('dhcp', sec, 'confdir');

	if (type(dir) == 'array')
		dir = dir[0];

	if (dir && substr(dir, 0, 1) == '/') {
		let comma = index(dir, ',');

		return comma >= 0 ? substr(dir, 0, comma) : dir;
	}

	return sprintf('/tmp/dnsmasq.%s.d', sec);
}

function rules_path() {
	return dnsmasq_confdir() + '/' + RULES_FILE;
}

/* Write the generated rules into the dnsmasq conf-dir. Returns true when
 * something changed, so that callers only reload dnsmasq when needed. */
function write_rules(content) {
	let path = rules_path();
	let old = fs.readfile(path);
	let text = content ? content + '\n' : '';

	/* No rules at all: drop the file instead of leaving an empty one. */
	if (!trim(text)) {
		if (old == null)
			return false;

		fs.unlink(path);
		return true;
	}

	if (text == old)
		return false;

	fs.mkdir(dnsmasq_confdir());

	/* Write a temporary file and rename it, an interrupted write must not
	 * leave a half written rules file behind. */
	let tmp = sprintf('%s.%d.tmp', path, clock()[1]);

	if (!fs.writefile(tmp, text)) {
		error(sprintf('failed to write %s', tmp));
		fs.unlink(tmp);
		return false;
	}

	if (!fs.rename(tmp, path)) {
		error(sprintf('failed to replace %s', path));
		fs.unlink(tmp);
		return false;
	}

	return true;
}

function render() {
	ensure_cache_dir();

	let dns_port = ctx.get(NAME, 'main', 'dns_port') || DNS_PORT_DEFAULT;
	let proxy = load_domains('proxy_domain', PROXY_CACHE);
	let bypass = load_domains('bypass_domain', BYPASS_CACHE);
	let final_proxy = length(bypass) ? filter_proxy(proxy, bypass) : proxy;
	let out = [];

	/* bypass domains only contribute an nftset entry, they are not
	 * resolved through sslocal */
	for (let d in bypass)
		push(out, sprintf('nftset=/%s/4#inet#%s#ss_rules_dst_bypass,6#inet#%s#ss_rules6_dst_bypass',
			d, NFT_TABLE, NFT_TABLE));

	/* proxy domains are resolved by sslocal and land in the forward set */
	for (let d in final_proxy) {
		push(out, sprintf('server=/%s/127.0.0.1#%s', d, dns_port));
		push(out, sprintf('nftset=/%s/4#inet#%s#ss_rules_dst_forward,6#inet#%s#ss_rules6_dst_forward',
			d, NFT_TABLE, NFT_TABLE));
	}

	info(sprintf('dnsmasq rules rendered: %d proxy, %d bypass',
		length(final_proxy), length(bypass)));

	return write_rules(join('\n', out));
}

/* ------------------------------------------------------------------ */
/* remote lists                                                        */

function refresh_one(option, cache_file) {
	let urls = uci_list('settings', option);

	ensure_cache_dir();

	/* No URL configured: drop the cache so stale entries disappear. */
	if (!length(urls)) {
		fs.unlink(cache_file);
		return;
	}

	let data = '';

	for (let url in urls) {
		if (!match(url, URL_RE)) {
			error(sprintf('invalid domain list URL "%s", skipped', url));
			continue;
		}

		let content = fetch(url);

		if (content) {
			data += content;

			if (!match(content, /\n$/))
				data += '\n';
		}
		else {
			error(sprintf('failed to download domain list "%s"', url));
		}
	}

	if (trim(data)) {
		let list = normalize(data);

		if (length(list)) {
			let text = join('\n', list) + '\n';

			/* Write through a temporary file: procd may stop the refresh
			 * instance in the middle of a download, a half written cache
			 * must never replace the last complete one. */
			let tmp = sprintf('%s.%d.tmp', cache_file, clock()[1]);

			if (fs.writefile(tmp, text) && fs.rename(tmp, cache_file))
				info(sprintf('updated cache %s (%d domains)', cache_file, length(list)));
			else {
				fs.unlink(tmp);
				error(sprintf('failed to write %s', cache_file));
			}

			return;
		}
	}

	info('domain list is empty, keeping the cached list');
}

function refresh_cache() {
	refresh_one('proxy_domain_url', PROXY_CACHE);
	refresh_one('bypass_domain_url', BYPASS_CACHE);
}

function nft_table_exists() {
	let p = fs.popen([ 'nft', 'list', 'tables' ], 'r');

	if (!p)
		return false;

	let out = p.read('all') ?? '';
	p.close();

	return index(out, NFT_TABLE) >= 0;
}

/* dnsmasq only re-reads the conf-dir on startup, a SIGHUP (the init script's
 * "reload") keeps serving the old rules. Restart it so a freshly written rules
 * file actually takes effect. */
function reload_dnsmasq() {
	let p = fs.popen([ '/etc/init.d/dnsmasq', 'restart' ], 'r');

	if (!p)
		return;

	p.read('all');
	p.close();
}

/* ------------------------------------------------------------------ */
/* main                                                                */

let cmd = ARGV[0];

if (cmd == 'render') {
	if (render())
		reload_dnsmasq();
}
else if (cmd == 'refresh') {
	refresh_cache();

	let ips_changed = refresh_ip_cache();

	/* The download may have taken minutes, re-read the configuration so
	 * that the render below does not overwrite changes made meanwhile
	 * with the values captured when this process started. */
	ctx = uci.cursor();

	if (nft_table_exists()) {
		let changed = render();

		/* The service may have been stopped while rendering, the
		 * nftables sets the rules refer to are gone in that case. */
		if (nft_table_exists()) {
			if (changed)
				reload_dnsmasq();

			if (ips_changed)
				reload_nft();
		}
		else {
			write_rules('');
			info('service stopped during refresh, dnsmasq left untouched');
		}
	}
	else {
		info('service stopped during refresh, dnsmasq left untouched');
	}
}
else if (cmd == 'remove') {
	if (write_rules(''))
		reload_dnsmasq();
}
else {
	warn('usage: dnsmasq.uc {render|refresh|remove}\n');
	exit(1);
}

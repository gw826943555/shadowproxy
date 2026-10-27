#!/usr/bin/ucode
'use strict';

/*
 * dnsmasq rule handling for shadowsocks-rust.
 *
 *   render   regenerate the dnsmasq block from the local UCI lists and the
 *            cached remote lists (no network access, fast)
 *   refresh  download the remote lists, update the cache, regenerate the
 *            dnsmasq block and reload dnsmasq (meant to run in background)
 *   remove   drop the shadowsocks-rust block from dnsmasq.conf
 *
 * The nftables ruleset is rendered separately from rules.uc.
 */

let fs = require('fs');
let uci = require('uci');

const NAME = 'shadowsocks-rust';
const CACHE_DIR = '/var/shadowsocks-rust';
const PROXY_CACHE = CACHE_DIR + '/proxy-domains.cache';
const BYPASS_CACHE = CACHE_DIR + '/bypass-domains.cache';
const LOCK_DIR = '/var/lock';
const LOCK = LOCK_DIR + '/' + NAME + '-refresh.lock';
const DNSMASQ_CONF = '/etc/dnsmasq.conf';
const DNSMASQ_BEGIN = '# BEGIN shadowsocks-rust';
const DNSMASQ_END = '# END shadowsocks-rust';
const NFT_TABLE = 'shadowsocks-rust-mangle';
const DNS_PORT_DEFAULT = 5300;
const LOCK_STALE = 900;
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
/* dnsmasq config                                                      */

function write_block(content) {
	let data = fs.readfile(DNSMASQ_CONF);

	/* Never rewrite a file we could not read, a truncation would destroy the
	 * user configuration. */
	if (data == null) {
		error(sprintf('cannot read %s, not touching it', DNSMASQ_CONF));
		return;
	}

	let out = [];
	let skip = false;

	for (let line in split(data, '\n')) {
		if (line == DNSMASQ_BEGIN) {
			skip = true;
			continue;
		}

		if (line == DNSMASQ_END) {
			skip = false;
			continue;
		}

		if (!skip)
			push(out, line);
	}

	while (length(out) && trim(out[length(out) - 1]) == '')
		pop(out);

	if (content) {
		push(out, DNSMASQ_BEGIN);

		for (let line in split(content, '\n'))
			push(out, line);

		push(out, DNSMASQ_END);
	}

	if (!fs.writefile(DNSMASQ_CONF, length(out) ? join('\n', out) + '\n' : ''))
		error(sprintf('failed to write %s', DNSMASQ_CONF));
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

	write_block(join('\n', out));
	info(sprintf('dnsmasq rules rendered: %d proxy, %d bypass',
		length(final_proxy), length(bypass)));
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
			if (fs.writefile(cache_file, join('\n', list) + '\n'))
				info(sprintf('updated cache %s (%d domains)', cache_file, length(list)));
			else
				error(sprintf('failed to write %s', cache_file));

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

function reload_dnsmasq() {
	let p = fs.popen([ '/etc/init.d/dnsmasq', 'reload' ], 'r');

	if (!p)
		return;

	p.read('all');
	p.close();
}

/* mkdir() returns null instead of throwing when the directory exists, an
 * atomic mkdir is the cheapest lock available on OpenWrt. A refresh killed
 * by the OOM handler leaves the directory behind, so drop it once it is
 * older than LOCK_STALE seconds and retry once. */
function lock_acquire() {
	fs.mkdir(LOCK_DIR);

	if (fs.mkdir(LOCK) != null)
		return true;

	let st = fs.stat(LOCK);

	if (!st || (time() - st.mtime) < LOCK_STALE)
		return false;

	info('removing stale refresh lock');

	fs.rmdir(LOCK);

	return fs.mkdir(LOCK) != null;
}

/* ------------------------------------------------------------------ */
/* main                                                                */

let cmd = ARGV[0];

if (cmd == 'render') {
	render();
}
else if (cmd == 'refresh') {
	if (!lock_acquire())
		exit(0);

	refresh_cache();

	/* The download may have taken minutes, re-read the configuration so
	 * that the render below does not overwrite changes made meanwhile
	 * with the values captured when this process started. */
	ctx = uci.cursor();

	if (nft_table_exists()) {
		render();

		/* The service may have been stopped while rendering, the
		 * nftables sets the block refers to are gone in that case. */
		if (nft_table_exists()) {
			reload_dnsmasq();
		}
		else {
			write_block('');
			info('service stopped during refresh, dnsmasq left untouched');
		}
	}
	else {
		info('service stopped during refresh, dnsmasq left untouched');
	}

	fs.rmdir(LOCK);
}
else if (cmd == 'remove') {
	write_block('');
}
else {
	warn('usage: dnsmasq.uc {render|refresh|remove}\n');
	exit(1);
}

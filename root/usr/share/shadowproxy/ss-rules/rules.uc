{%
let uci = require("uci");
let fs = require("fs");

let dir = "/usr/share/shadowproxy/ss-rules";
let cur = uci.cursor();

function get_opt(sec, name, def) {
	let v = cur.get("shadowproxy", sec, name);
	return (v == null || v == "") ? def : v;
}

function get_list(sec, name) {
	let v = cur.get("shadowproxy", sec, name);
	if (v == null)
		return [];
	return type(v) == "array" ? v : split(v, /[ \t\n]+/);
}

let v4_re = /^[0-9.]+(\/[0-9]+)?$/;
let v6_re = /^[0-9a-fA-F:.]+(\/[0-9]+)?$/;

function clean(list, af) {
	let res = [];
	let seen = {};
	for (let a in list) {
		a = trim(a);
		if (!a || seen[a])
			continue;
		let is6 = index(a, ":") != -1;
		if (is6 != (af == 6))
			continue;
		if (!match(a, is6 ? v6_re : v4_re))
			continue;
		seen[a] = true;
		push(res, a);
	}
	return res;
}

let private_v4 = [
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
];

let private_v6 = [
	"::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48",
	"100::/64", "fe80::/10", "2001::/23", "fc00::/7",
];

let cfg = json(fs.readfile("/var/shadowproxy/config.json") || "{}");

let lists = {
	src_bypass: get_list("settings", "src_bypass"),
	src_forward: get_list("settings", "src_forward"),
	src_checkdst: get_list("settings", "src_checkdst"),
	dst_bypass: get_list("settings", "bypass_ipset"),
	dst_forward: get_list("settings", "proxy_ipset"),
};

for (let a in private_v4) push(lists.dst_bypass, a);
for (let a in private_v6) push(lists.dst_bypass, a);
for (let s in (cfg.servers || [])) {
	if (s.server)
		push(lists.dst_bypass, s.server);
}

let sets = {};
for (let name in keys(lists))
	sets[name] = { v4: clean(lists[name], 4), v6: clean(lists[name], 6) };

let policy = {
	src: get_opt("settings", "src_default", "accept"),
	dst: get_opt("settings", "dst_default", "accept"),
	local: get_opt("settings", "local_default", "none"),
};

let redir_port = get_opt("main", "redir_port", "60080");
%}
table inet shadowproxy-mangle {
{% include(dir + "/set.uc", { sets: sets }); %}
{% include(dir + "/chain.uc", { policy: policy, redir_port: redir_port }); %}
}

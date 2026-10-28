{%
function src_verdict(v) {
	if (v == "checkdst")
		return "goto ss_rules_dst";
	if (v == "forward")
		return "goto ss_rules_forward";
	return "accept";
}

function dst_verdict(v, target) {
	if (v == "forward")
		return "goto " + target;
	return "accept";
}
%}
{% if (policy.dns_hijack): %}
# Redirect DNS from LAN clients to the local dnsmasq. The matching accept
# rules in ss_rules_pre keep the tproxy rules away from these packets.
chain ss_dns_hijack {
	type nat hook prerouting priority dstnat; policy accept;
	iifname "{{ policy.lan_dev }}" udp dport 53 redirect to :53;
	iifname "{{ policy.lan_dev }}" tcp dport 53 redirect to :53;
}
{% endif %}

chain ss_rules_pre {
	type filter hook prerouting priority mangle; policy accept;
	ip daddr @ss_rules_dst_bypass accept;
	ip6 daddr @ss_rules6_dst_bypass accept;
{% if (policy.dns_hijack): %}
	iifname "{{ policy.lan_dev }}" udp dport 53 accept;
	iifname "{{ policy.lan_dev }}" tcp dport 53 accept;
{% endif %}
	meta mark 100 goto ss_rules_forward;
	meta l4proto { tcp, udp } goto ss_rules_src;
}

chain ss_rules_src {
	ip saddr @ss_rules_src_bypass accept;
	ip6 saddr @ss_rules6_src_bypass accept;
	ip saddr @ss_rules_src_forward goto ss_rules_forward;
	ip6 saddr @ss_rules6_src_forward goto ss_rules_forward;
	ip saddr @ss_rules_src_checkdst goto ss_rules_dst;
	ip6 saddr @ss_rules6_src_checkdst goto ss_rules_dst;
	{{ src_verdict(policy.src) }};
}

chain ss_rules_dst {
	ip daddr @ss_rules_dst_forward goto ss_rules_forward;
	ip6 daddr @ss_rules6_dst_forward goto ss_rules_forward;
	{{ dst_verdict(policy.dst, "ss_rules_forward") }};
}

chain ss_rules_forward {
	meta l4proto tcp meta mark set 100 tproxy to :{{ redir_port }};
	meta l4proto udp meta mark set 100 tproxy to :{{ redir_port }};
}
{% if (policy.local != "none"): %}

chain ss_rules_local {
	type route hook output priority mangle; policy accept;
	ct direction reply accept;
	meta mark 255 accept;
	ip daddr @ss_rules_dst_bypass accept;
	ip6 daddr @ss_rules6_dst_bypass accept;
	meta l4proto { tcp, udp } goto {{ policy.local == "forward" ? "ss_rules_local_forward" : "ss_rules_local_dst" }};
}
{%	if (policy.local == "checkdst"): %}

chain ss_rules_local_dst {
	ip daddr @ss_rules_dst_forward goto ss_rules_local_forward;
	ip6 daddr @ss_rules6_dst_forward goto ss_rules_local_forward;
	{{ dst_verdict(policy.dst, "ss_rules_local_forward") }};
}
{%	endif %}

chain ss_rules_local_forward {
	meta l4proto { tcp, udp } meta mark set 100;
}
{% endif %}

{%
let names = ["src_bypass", "src_forward", "src_checkdst", "dst_bypass", "dst_forward"];
%}
{% for (let name in names): for (let af in [4, 6]): %}
set {{ af == 4 ? "ss_rules_" : "ss_rules6_" }}{{ name }} {
	type ipv{{ af }}_addr;
	flags interval;
	auto-merge;
{%	let elems = sets[name][af == 4 ? "v4" : "v6"]; if (length(elems)): %}
	elements = { {{ join(", ", elems) }} }
{%	endif %}
}
{% endfor; endfor %}

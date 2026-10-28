'use strict';
'require tools.views as views';

// Reuse LuCI's LogreadBox, the same component behind Status -> System Log.
// It brings the facility/severity filters, the max rows selector and the
// periodic refresh; only the default filter differs here. The empty log tag
// disables its built-in single-tag filter so that both the sslocal output
// (tag "sslocal") and the init script messages (tag "shadowsocks-rust")
// can be kept.
var LogreadBox = views.LogreadBox('', _('Shadowsocks-Rust Log'));
var retrieveLog = LogreadBox.prototype.retrieveLog;

return LogreadBox.extend({
	retrieveLog: function() {
		return retrieveLog.call(this).then(function(res) {
			var lines = (res.value || '').split('\n').filter(function(line) {
				return /sslocal|shadowsocks-rust/.test(line);
			});

			return {
				value: lines.join('\n'),
				rows: lines.length + 1
			};
		});
	}
});

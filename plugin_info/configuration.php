<?php
if (!isConnect('admin')) {
	throw new Exception('{{401 - Accès non autorisé}}');
}
?>
<form class="form-horizontal">
	<div class="alert alert-info">
		<i class="fas fa-info-circle"></i>
		{{Chaque certificat est un équipement du plugin : les domaines, l'autorité, la méthode de validation et l'installation dans le serveur web se règlent sur sa fiche. Les réglages ci-dessous s'appliquent à tous. Le niveau du journal « acme » se règle plus bas, dans le cadre Logs de cette page.}}
	</div>

	<fieldset>
		<legend><i class="fas fa-envelope"></i> {{Contact}}</legend>
		<div class="form-group">
			<label class="col-lg-4 control-label">{{E-mail de contact par défaut}}</label>
			<div class="col-lg-3">
				<input type="email" class="configKey form-control" data-l1key="email" placeholder="admin@mondomaine.fr" />
			</div>
			<div class="col-lg-5">
				<span class="help-block">{{Transmis à l'autorité à la création du compte ACME, et utilisé par les équipements qui n'en précisent pas. Facultatif pour Let's Encrypt, obligatoire pour ZeroSSL. Let's Encrypt n'envoie plus d'e-mail d'expiration depuis 2025 : c'est le plugin qui prévient.}}</span>
			</div>
		</div>
	</fieldset>

	<fieldset>
		<legend><i class="fas fa-bell"></i> {{Alertes}}</legend>
		<div class="form-group">
			<label class="col-lg-4 control-label">{{Alerter avant l'expiration}}</label>
			<div class="col-lg-2">
				<div class="input-group">
					<input type="number" min="1" max="60" step="1" class="configKey form-control" data-l1key="alert_days" />
					<span class="input-group-addon">{{jours}}</span>
				</div>
			</div>
			<div class="col-lg-6">
				<span class="help-block">{{Quand un certificat expire dans moins de ce nombre de jours sans avoir été renouvelé, une alerte part chaque jour : dans le centre de messages de Jeedom, et par les actions (mail, Telegram, SMS…) de l'onglet Notifications de chaque équipement. 14 jours par défaut.}}</span>
			</div>
		</div>
	</fieldset>

	<fieldset>
		<legend><i class="fas fa-server"></i> {{Compatibilité du système}}</legend>
		<div class="form-group">
			<label class="col-lg-4 control-label">{{Installation automatique en HTTPS}}</label>
			<div class="col-lg-8">
				<a class="btn btn-default btn-sm" id="bt_acmeDetect"><i class="fas fa-search"></i> {{Analyser le système}}</a>
				<span class="help-block">{{Détecte le système, le serveur web, Docker et le module SSL, et indique si le plugin sait installer le certificat tout seul. L'émission du certificat, elle, fonctionne partout.}}</span>
				<div id="div_acmeDetect" style="display:none;margin-top:8px;"></div>
			</div>
		</div>
	</fieldset>
</form>

<script>
/*
 * Analyse du système : appel à core/ajax/acme.ajax.php (action detectSystem),
 * qui interroge resources/acme_webserver.sh detect. fetch direct plutôt que
 * domUtils.ajax : l'ajax du plugin exige l'en-tête X-Requested-With.
 */
(function() {
	var button = document.getElementById('bt_acmeDetect')
	var target = document.getElementById('div_acmeDetect')
	if (!button || !target) {
		return
	}
	var labels = {
		os_id: '{{Système}}',
		os_version: '{{Version}}',
		webserver: '{{Serveur web}}',
		layout: '{{Famille}}',
		docker: 'Docker',
		systemd: 'systemd',
		ssl_module: '{{Module SSL}}',
		supported: '{{Installation automatique}}',
		reason: '{{Raison}}'
	}
	function yesNo(value) {
		return (String(value) === '1') ? '{{oui}}' : '{{non}}'
	}
	button.addEventListener('click', function() {
		button.classList.add('disabled')
		target.style.display = ''
		target.className = 'alert alert-info'
		target.textContent = '{{Analyse en cours…}}'
		var body = new URLSearchParams()
		body.append('action', 'detectSystem')
		fetch('plugins/acme/core/ajax/acme.ajax.php', {
			method: 'POST',
			body: body,
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'X-Requested-With': 'XMLHttpRequest' }
		}).then(function(response) {
			return response.json()
		}).then(function(data) {
			button.classList.remove('disabled')
			if (!data || data.state !== 'ok') {
				target.className = 'alert alert-danger'
				target.textContent = (data && data.result) ? String(data.result) : '{{Erreur inconnue}}'
				return
			}
			var result = data.result || {}
			var supported = String(result.supported) === '1'
			target.className = supported ? 'alert alert-success' : 'alert alert-warning'
			target.textContent = ''
			var title = document.createElement('strong')
			title.textContent = supported
				? '{{Le plugin peut installer le certificat dans le serveur web de ce système.}}'
				: "{{L'installation automatique n'est pas possible ici : le certificat reste utilisable en le téléchargeant (proxy inverse, NAS, configuration manuelle).}}"
			target.appendChild(title)
			var table = document.createElement('table')
			table.className = 'table table-condensed'
			table.style.marginTop = '8px'
			table.style.marginBottom = '0'
			var keys = Object.keys(labels)
			for (var k in result) {
				if (Object.prototype.hasOwnProperty.call(result, k) && keys.indexOf(k) < 0) {
					keys.push(k)
				}
			}
			keys.forEach(function(key) {
				if (!Object.prototype.hasOwnProperty.call(result, key)) {
					return
				}
				var tr = document.createElement('tr')
				var th = document.createElement('td')
				th.style.width = '220px'
				th.textContent = labels[key] || key
				var td = document.createElement('td')
				var value = result[key]
				if (['docker', 'systemd', 'ssl_module', 'supported'].indexOf(key) >= 0) {
					value = yesNo(value)
				}
				td.textContent = (value === null || value === undefined) ? '' : String(value)
				tr.appendChild(th)
				tr.appendChild(td)
				table.appendChild(tr)
			})
			target.appendChild(table)
		}).catch(function(error) {
			button.classList.remove('disabled')
			target.className = 'alert alert-danger'
			target.textContent = '{{Serveur Jeedom injoignable.}}'
		})
	})
})()
</script>

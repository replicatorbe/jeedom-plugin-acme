<?php
if (!isConnect('admin')) {
	throw new Exception('{{401 - Accès non autorisé}}');
}
/*
 * Page du plugin ACME : un équipement = un certificat.
 *
 * Les champs des fournisseurs DNS sont rendus ici, côté serveur, à partir de
 * getFields() : ce sont de vrais eqLogicAttr (configuration / dns_<champ>),
 * chargés et enregistrés par le coeur comme les autres. Le JS ne fait que
 * montrer ceux du fournisseur choisi.
 */
$plugin = plugin::byId('acme');
sendVarToJS('eqType', $plugin->getId());
$eqLogics = eqLogic::byType($plugin->getId());
class_exists('acme');

$dnsProviders = array();
$ovhTokenUrls = array();
try {
	foreach (acmeDns::providers() as $providerId => $class) {
		$dnsProviders[$providerId] = array('label' => $class::getLabel(), 'fields' => $class::getFields());
	}
	if (class_exists('acmeDnsOvh') && isset($dnsProviders['ovh']['fields']['endpoint']['options'])) {
		foreach (array_keys($dnsProviders['ovh']['fields']['endpoint']['options']) as $endpoint) {
			$ovhTokenUrls[$endpoint] = acmeDnsOvh::createTokenUrl((string) $endpoint);
		}
	}
} catch (Throwable $e) {
	log::add('acme', 'error', 'desktop : ' . $e->getMessage());
}
sendVarToJS('acmeOvhTokenUrls', $ovhTokenUrls);
sendVarToJS('acmeNotifyEvents', acme::notifyEvents());
sendVarToJS('acmeNotifyDefaults', acme::notifyDefaultEvents());

/* Un champ de fournisseur, en eqLogicAttr. data-default porte la valeur par
 * défaut, que le JS applique quand l'équipement n'en a pas encore.
 * Libellés, aides et options viennent de getFields() : des chaînes
 * dynamiques, que les doubles accolades ne peuvent pas traduire. Elles passent donc par __(),
 * et leurs traductions sont rangées dans en_US.json sous la clé de ce
 * fichier (plugins/acme/desktop/php/acme.php). */
function acmeRenderDnsField($key, $field) {
	$l2key = 'dns_' . $key;
	$label = __(isset($field['label']) ? (string) $field['label'] : (string) $key, __FILE__);
	$type = isset($field['type']) ? $field['type'] : 'text';
	$default = isset($field['default']) ? (string) $field['default'] : '';
	$html = '<div class="form-group">';
	$html .= '<label class="col-sm-4 control-label">' . htmlspecialchars($label) . '</label>';
	$html .= '<div class="col-sm-8">';
	if ($type === 'select') {
		$html .= '<select class="eqLogicAttr form-control acmeDnsInput" data-l1key="configuration" data-l2key="' . htmlspecialchars($l2key) . '" data-field="' . htmlspecialchars($key) . '" data-default="' . htmlspecialchars($default) . '">';
		$options = isset($field['options']) && is_array($field['options']) ? $field['options'] : array();
		foreach ($options as $value => $text) {
			$html .= '<option value="' . htmlspecialchars((string) $value) . '">' . htmlspecialchars(__((string) $text, __FILE__)) . '</option>';
		}
		$html .= '</select>';
	} else {
		$inputType = ($type === 'password') ? 'password' : 'text';
		$html .= '<input type="' . $inputType . '" class="eqLogicAttr form-control acmeDnsInput" data-l1key="configuration" data-l2key="' . htmlspecialchars($l2key) . '" data-field="' . htmlspecialchars($key) . '" data-default="' . htmlspecialchars($default) . '" autocomplete="' . ($inputType === 'password' ? 'new-password' : 'off') . '">';
	}
	if (!empty($field['help'])) {
		$html .= '<span class="help-block" style="margin:4px 0 0 0;">' . htmlspecialchars(__((string) $field['help'], __FILE__)) . '</span>';
	}
	$html .= '</div></div>';
	return $html;
}
?>

<div class="row row-overflow">
	<div class="col-xs-12 eqLogicThumbnailDisplay">
		<legend><i class="fas fa-cog"></i> {{Gestion}}</legend>
		<div class="eqLogicThumbnailContainer">
			<div class="cursor eqLogicAction logoPrimary" data-action="add">
				<i class="fas fa-plus-circle"></i>
				<br>
				<span>{{Ajouter un certificat}}</span>
			</div>
			<div class="cursor eqLogicAction logoSecondary" data-action="gotoPluginConf">
				<i class="fas fa-wrench"></i>
				<br>
				<span>{{Configuration}}</span>
			</div>
		</div>

		<legend><i class="fas fa-lock"></i> {{Mes certificats}}</legend>
		<?php
		if (count($eqLogics) == 0) {
			echo '<div class="alert alert-info" style="margin:5px;">';
			echo '<b>{{Aucun certificat pour le moment. Pour démarrer :}}</b>';
			echo '<ol style="margin:5px 0 0 0;padding-left:20px;">';
			echo '<li>{{Il faut un nom de domaine public qui désigne ce Jeedom, par exemple jeedom.mondomaine.fr. Un nom en .local ou une adresse IP ne peuvent pas être certifiés.}}</li>';
			echo '<li>{{Ajoutez un certificat, saisissez le domaine, et choisissez la validation DNS-01 si votre DNS est chez un fournisseur pris en charge (OVHcloud) : aucun port à ouvrir.}}</li>';
			echo '<li>{{Faites d\'abord « Tester (staging) » : un essai complet, sans limite de taux, qui n\'installe rien. Puis « Obtenir le certificat ».}}</li>';
			echo '<li>{{Installez-le dans le serveur web (bouton « Installer dans le serveur web », ou cochez l\'installation automatique avant d\'obtenir le certificat). Vérifiez que https://&lt;votre nom&gt; s\'ouvre sans alerte, et seulement ensuite activez la redirection HTTP vers HTTPS.}}</li>';
			echo '</ol>';
			echo '<div style="margin-top:5px;">{{Depuis le réseau local, le nom doit désigner l\'adresse IP locale de Jeedom : DNS local (routeur, Pi-hole…), ou enregistrement A public vers l\'adresse privée, ou NAT loopback du routeur. Sinon le navigateur ne trouvera pas Jeedom par ce nom.}}</div>';
			echo '</div>';
		}
		echo '<div class="input-group" style="margin:5px;">';
		echo '<input class="form-control roundedLeft" placeholder="{{Rechercher}}" id="in_searchEqlogic">';
		echo '<div class="input-group-btn">';
		echo '<a id="bt_resetSearch" class="btn" style="width:30px"><i class="fas fa-times"></i></a>';
		echo '<a class="btn roundedRight hidden" id="bt_pluginDisplayAsTable" data-coreSupport="1" data-state="0"><i class="fas fa-grip-lines"></i></a>';
		echo '</div>';
		echo '</div>';
		echo '<div class="eqLogicThumbnailContainer">';
		foreach ($eqLogics as $eqLogic) {
			$opacity = ($eqLogic->getIsEnable()) ? '' : 'disableCard';
			echo '<div class="eqLogicDisplayCard cursor ' . $opacity . '" data-eqLogic_id="' . $eqLogic->getId() . '">';
			echo '<img src="' . $plugin->getPathImgIcon() . '">';
			echo '<br>';
			echo '<span class="name">' . $eqLogic->getHumanName(true, true) . '</span>';
			echo '<span class="hiddenAsCard displayTableRight hidden">';
			echo ($eqLogic->getIsVisible() == 1) ? '<i class="fas fa-eye" title="{{Equipement visible}}"></i>' : '<i class="fas fa-eye-slash" title="{{Equipement non visible}}"></i>';
			echo '</span>';
			echo '</div>';
		}
		echo '</div>';
		?>
	</div>

	<div class="col-xs-12 eqLogic" style="display: none;">
		<div class="input-group pull-right" style="display:inline-flex">
			<span class="input-group-btn">
				<a class="btn btn-default btn-sm eqLogicAction roundedLeft" data-action="configure"><i class="fas fa-cogs"></i><span class="hidden-xs"> {{Configuration avancée}}</span></a>
				<a class="btn btn-sm btn-success eqLogicAction" data-action="save"><i class="fas fa-check-circle"></i> {{Sauvegarder}}</a>
				<a class="btn btn-sm btn-danger eqLogicAction roundedRight" data-action="remove"><i class="fas fa-minus-circle"></i> {{Supprimer}}</a>
			</span>
		</div>
		<ul class="nav nav-tabs" role="tablist">
			<li role="presentation"><a href="#" class="eqLogicAction" aria-controls="home" role="tab" data-toggle="tab" data-action="returnToThumbnailDisplay"><i class="fas fa-arrow-circle-left"></i></a></li>
			<li role="presentation" class="active"><a href="#eqlogictab" aria-controls="home" role="tab" data-toggle="tab"><i class="fas fa-lock"></i><span class="hidden-xs"> {{Équipement}}</span></a></li>
			<li role="presentation"><a href="#notifytab" aria-controls="home" role="tab" data-toggle="tab"><i class="fas fa-bell"></i><span class="hidden-xs"> {{Notifications}}</span></a></li>
			<li role="presentation"><a href="#commandtab" aria-controls="home" role="tab" data-toggle="tab"><i class="fas fa-list"></i><span class="hidden-xs"> {{Commandes}}</span></a></li>
		</ul>

		<div class="tab-content">
			<!-- ========================= ÉQUIPEMENT ========================= -->
			<div role="tabpanel" class="tab-pane active" id="eqlogictab">
				<br>
				<div class="col-lg-6">
					<form class="form-horizontal">
						<fieldset>
							<legend><i class="fas fa-tag"></i> {{Général}}</legend>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Nom}}</label>
								<div class="col-sm-8">
									<input type="text" class="eqLogicAttr form-control" data-l1key="id" style="display:none;">
									<input type="text" class="eqLogicAttr form-control" data-l1key="name" placeholder="{{Certificat}}">
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Objet parent}}</label>
								<div class="col-sm-8">
									<select class="eqLogicAttr form-control" data-l1key="object_id">
										<option value="">{{Aucun}}</option>
										<?php
										foreach ((jeeObject::buildTree(null, false)) as $object) {
											echo '<option value="' . $object->getId() . '">' . $object->getHumanName(true, true) . '</option>';
										}
										?>
									</select>
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Catégorie}}</label>
								<div class="col-sm-8">
									<?php
									foreach (jeedom::getConfiguration('eqLogic:category') as $key => $value) {
										echo '<label class="checkbox-inline">';
										echo '<input type="checkbox" class="eqLogicAttr" data-l1key="category" data-l2key="' . $key . '">' . $value['name'];
										echo '</label>';
									}
									?>
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Options}}</label>
								<div class="col-sm-8">
									<label class="checkbox-inline"><input type="checkbox" class="eqLogicAttr" data-l1key="isEnable" checked>{{Activer}}</label>
									<label class="checkbox-inline"><input type="checkbox" class="eqLogicAttr" data-l1key="isVisible" checked>{{Visible}}</label>
								</div>
							</div>
						</fieldset>

						<fieldset>
							<legend><i class="fas fa-certificate"></i> {{Certificat}}</legend>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Domaines}}</label>
								<div class="col-sm-8">
									<textarea class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="domains" rows="3" placeholder="jeedom.mondomaine.fr"></textarea>
									<span class="help-block" style="margin:4px 0 0 0;">{{Un nom par ligne (ou séparés par des virgules). Le premier est le nom principal. Un nom générique *.mondomaine.fr exige la validation DNS-01. Le nom doit être public : pas de nom se terminant par .local, .lan ou .home, pas d'adresse IP.}}</span>
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Autorité}}</label>
								<div class="col-sm-8">
									<select class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="ca" id="sel_acmeCa" data-default="letsencrypt">
										<option value="letsencrypt">Let's Encrypt</option>
										<option value="letsencrypt_staging">{{Let's Encrypt staging (test, certificats non reconnus par les navigateurs)}}</option>
										<option value="zerossl">ZeroSSL</option>
										<option value="custom">{{Autre autorité ACME (URL)}}</option>
									</select>
								</div>
							</div>
							<div class="form-group acmeCa acmeCa-custom">
								<label class="col-sm-4 control-label">{{URL de l'annuaire ACME}}</label>
								<div class="col-sm-8">
									<input type="text" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="directory_url" placeholder="https://acme.exemple.com/directory">
								</div>
							</div>
							<div class="form-group acmeCa acmeCa-custom acmeCa-zerossl">
								<label class="col-sm-4 control-label">{{EAB : Key ID}}</label>
								<div class="col-sm-8">
									<input type="text" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="eab_kid" autocomplete="off">
								</div>
							</div>
							<div class="form-group acmeCa acmeCa-custom acmeCa-zerossl">
								<label class="col-sm-4 control-label">{{EAB : clé HMAC}}</label>
								<div class="col-sm-8">
									<input type="password" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="eab_hmac" autocomplete="new-password">
									<span class="help-block acmeCa acmeCa-zerossl" style="margin:4px 0 0 0;">{{ZeroSSL : laissez ces deux champs vides, le plugin obtient les identifiants EAB tout seul à partir de l'adresse e-mail, puis les mémorise ici.}}</span>
									<span class="help-block acmeCa acmeCa-custom" style="margin:4px 0 0 0;">{{Seulement si l'autorité exige un compte externe (External Account Binding) ; elle fournit alors ces deux valeurs.}}</span>
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{E-mail de contact}}</label>
								<div class="col-sm-8">
									<input type="email" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="email" placeholder="{{vide = celui de la configuration du plugin}}">
									<span class="help-block acmeCa acmeCa-zerossl" style="margin:4px 0 0 0;">{{Obligatoire pour ZeroSSL (ici ou dans la configuration du plugin).}}</span>
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Type de clé}}</label>
								<div class="col-sm-8">
									<select class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="key_type" data-default="ec256">
										<option value="ec256">{{ECDSA P-256 (recommandé)}}</option>
										<option value="ec384">ECDSA P-384</option>
										<option value="rsa2048">RSA 2048</option>
										<option value="rsa4096">RSA 4096</option>
									</select>
									<span class="help-block" style="margin:4px 0 0 0;">{{Une clé neuve est générée à chaque renouvellement. RSA seulement pour de vieux clients qui ne connaissent pas ECDSA.}}</span>
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Renouveler}}</label>
								<div class="col-sm-8">
									<div class="input-group">
										<input type="number" min="1" max="90" step="1" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="renew_before_days" placeholder="{{automatique}}">
										<span class="input-group-addon">{{jours avant l'expiration}}</span>
									</div>
									<span class="help-block" style="margin:4px 0 0 0;">{{Vide : au dernier tiers de la durée de vie du certificat (30 jours avant la fin pour un certificat de 90 jours). Le renouvellement est vérifié chaque jour.}}</span>
								</div>
							</div>
						</fieldset>

						<fieldset>
							<legend><i class="fas fa-check-double"></i> {{Validation}}</legend>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Méthode}}</label>
								<div class="col-sm-8">
									<select class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="challenge" id="sel_acmeChallenge" data-default="dns-01">
										<option value="dns-01">{{DNS-01 (recommandé)}}</option>
										<option value="http-01">HTTP-01</option>
									</select>
								</div>
							</div>
							<div class="form-group acmeChallenge acmeChallenge-dns-01">
								<div class="col-sm-offset-4 col-sm-8">
									<div class="alert alert-info" style="margin-bottom:0;">
										{{DNS-01 : le plugin prouve qu'il contrôle le domaine en posant un enregistrement TXT par l'API de votre fournisseur DNS. Rien à ouvrir sur le routeur, fonctionne pour un Jeedom purement local, et permet les noms génériques (*.mondomaine.fr).}}
									</div>
								</div>
							</div>
							<div class="form-group acmeChallenge acmeChallenge-http-01">
								<div class="col-sm-offset-4 col-sm-8">
									<div class="alert alert-warning" style="margin-bottom:0;">
										{{HTTP-01 : l'autorité vient lire un fichier sur http://&lt;domaine&gt;/.well-known/acme-challenge/, TOUJOURS sur le port 80 de l'adresse publique du nom. Il faut donc une redirection du routeur « port public 80 → Jeedom:80 ». Une redirection d'un autre port (par exemple 9002 → 80) ne suffit pas : l'autorité ne suit les redirections que vers les ports 80 et 443. Pas de nom générique en HTTP-01.}}
									</div>
								</div>
							</div>
							<div class="form-group acmeChallenge acmeChallenge-http-01">
								<label class="col-sm-4 control-label">{{Racine web}}</label>
								<div class="col-sm-8">
									<input type="text" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="webroot" placeholder="<?php echo htmlspecialchars(acme::jeedomRoot()); ?>">
									<span class="help-block" style="margin:4px 0 0 0;">{{Dossier servi par le serveur web sur le port 80. Vide : la racine de Jeedom.}}</span>
								</div>
							</div>
							<div class="form-group acmeChallenge acmeChallenge-dns-01">
								<label class="col-sm-4 control-label">{{Fournisseur DNS}}</label>
								<div class="col-sm-8">
									<select class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="dns_provider" id="sel_acmeDnsProvider" data-default="ovh">
										<?php
										foreach ($dnsProviders as $providerId => $provider) {
											echo '<option value="' . htmlspecialchars($providerId) . '">' . htmlspecialchars($provider['label']) . '</option>';
										}
										?>
									</select>
								</div>
							</div>
							<?php
							$rendered = array();
							foreach ($dnsProviders as $providerId => $provider) {
								echo '<div class="acmeChallenge acmeChallenge-dns-01"><div class="acmeDnsProvider" data-provider="' . htmlspecialchars($providerId) . '">';
								foreach ($provider['fields'] as $key => $field) {
									/* Deux fournisseurs partageant un nom de champ partagent la
									 * même clé dns_<champ> : un seul champ, sinon ils s'écraseraient. */
									if (isset($rendered[$key])) {
										continue;
									}
									$rendered[$key] = true;
									echo acmeRenderDnsField($key, $field);
									/* Le jeton se crée pour le point d'accès choisi : le bouton
									 * vient juste après lui, avant les clés qu'il fournit. */
									if ($providerId === 'ovh' && $key === 'endpoint') {
										echo '<div class="form-group"><div class="col-sm-offset-4 col-sm-8">';
										echo '<a class="btn btn-default btn-sm" id="a_acmeOvhToken" target="_blank" rel="noopener noreferrer" href="#"><i class="fas fa-key"></i> {{Créer un jeton OVH}}</a>';
										echo '<span class="help-block" style="margin:4px 0 0 0;">{{Ouvre la page de création de jeton d\'OVHcloud pour le point d\'accès choisi, avec des droits limités à la zone DNS (GET, POST, DELETE sur /domain/zone/*). Recopiez ensuite les trois clés ci-dessous.}}</span>';
										echo '</div></div>';
									}
								}
								echo '</div></div>';
							}
							?>
							<div class="form-group acmeChallenge acmeChallenge-dns-01">
								<label class="col-sm-4 control-label">{{Attente de propagation}}</label>
								<div class="col-sm-8">
									<div class="input-group">
										<input type="number" min="30" max="3600" step="10" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="dns_propagation_timeout" placeholder="300">
										<span class="input-group-addon">s</span>
									</div>
									<span class="help-block" style="margin:4px 0 0 0;">{{Temps maximal d'attente pour que l'enregistrement TXT soit visible sur tous les serveurs DNS du domaine.}}</span>
								</div>
							</div>
							<div class="form-group acmeChallenge acmeChallenge-dns-01">
								<div class="col-sm-offset-4 col-sm-8">
									<a class="btn btn-default btn-sm" id="bt_acmeTestDns"><i class="fas fa-plug"></i> {{Tester l'accès DNS}}</a>
									<span class="help-block" style="margin:4px 0 0 0;">{{Vérifie les clés et les droits auprès du fournisseur avec les valeurs saisies, sans rien modifier dans la zone.}}</span>
									<div id="div_acmeTestDns" style="display:none;margin-top:8px;"></div>
								</div>
							</div>
						</fieldset>
					</form>
				</div>

				<div class="col-lg-6">
					<form class="form-horizontal">
						<fieldset>
							<legend><i class="fas fa-server"></i> {{Serveur web}}</legend>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Installation automatique}}</label>
								<div class="col-sm-8">
									<label class="checkbox-inline"><input type="checkbox" class="eqLogicAttr" data-l1key="configuration" data-l2key="install_webserver">{{Installer automatiquement dans le serveur web de Jeedom}}</label>
									<span class="help-block" style="margin:4px 0 0 0;">{{Après chaque émission ou renouvellement, le certificat est copié dans /etc/ssl/jeedom-acme/ et le serveur web est configuré en HTTPS, puis rechargé en douceur.}}</span>
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Port HTTPS}}</label>
								<div class="col-sm-8">
									<input type="number" min="1" max="65535" step="1" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="https_port" placeholder="443">
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Redirection}}</label>
								<div class="col-sm-8">
									<label class="checkbox-inline"><input type="checkbox" class="eqLogicAttr" data-l1key="configuration" data-l2key="redirect_https">{{Rediriger HTTP vers HTTPS}}</label>
									<span class="help-block" style="margin:4px 0 0 0;">{{Toute visite en http:// part vers https://, sauf /.well-known/acme-challenge/ (nécessaire au HTTP-01). À n'activer qu'une fois l'accès HTTPS vérifié.}}</span>
								</div>
							</div>
							<div class="form-group">
								<label class="col-sm-4 control-label">{{Port HTTPS public}}</label>
								<div class="col-sm-8">
									<input type="number" min="1" max="65535" step="1" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="public_https_port" placeholder="{{identique au port HTTPS}}">
									<span class="help-block" style="margin:4px 0 0 0;">{{Port par lequel on joint Jeedom en HTTPS depuis Internet, si votre routeur le publie sur un autre port (ex. port public 9003 redirigé vers Jeedom:443). La redirection HTTP → HTTPS envoie vers ce port. Laissez vide si le port public est le même que le port HTTPS.}}</span>
								</div>
							</div>
							<div class="form-group">
								<div class="col-sm-offset-4 col-sm-8">
									<div class="alert alert-warning" style="margin-bottom:0;">
										<i class="fas fa-exclamation-triangle"></i>
										{{Le plugin modifie la configuration du serveur web, en root. Il sauvegarde l'existant, teste la nouvelle configuration et revient en arrière si le test échoue ; mais vérifiez l'accès en https:// avant d'activer la redirection, et gardez un accès en http:// par l'adresse IP locale tant que ce n'est pas fait. Désactiver ou supprimer le plugin ne retire PAS la configuration HTTPS : utilisez « Désinstaller du serveur web ». Sous Docker, publiez aussi le port HTTPS du conteneur.}}
									</div>
								</div>
							</div>
						</fieldset>

						<fieldset>
							<legend><i class="fas fa-play-circle"></i> {{Actions}}</legend>
							<div class="form-group">
								<div class="col-sm-12">
									<a class="btn btn-default btn-sm acmeAction" data-job="staging"><i class="fas fa-flask"></i> {{Tester (staging)}}</a>
									<a class="btn btn-success btn-sm acmeAction" data-job="issue"><i class="fas fa-certificate"></i> {{Obtenir le certificat}}</a>
									<a class="btn btn-warning btn-sm acmeAction" data-job="renew"><i class="fas fa-sync"></i> {{Renouveler maintenant}}</a>
								</div>
							</div>
							<div class="form-group">
								<div class="col-sm-12">
									<a class="btn btn-primary btn-sm acmeAction" data-job="install"><i class="fas fa-download"></i> {{Installer dans le serveur web}}</a>
									<a class="btn btn-danger btn-sm acmeAction" data-job="uninstall"><i class="fas fa-times-circle"></i> {{Désinstaller du serveur web}}</a>
								</div>
							</div>
							<div class="form-group">
								<div class="col-sm-12">
									<a class="btn btn-default btn-sm acmeDownload" data-file="fullchain"><i class="fas fa-file-download"></i> {{Télécharger fullchain}}</a>
									<a class="btn btn-default btn-sm acmeDownload" data-file="privkey"><i class="fas fa-key"></i> {{Télécharger la clé}}</a>
									<a class="btn btn-default btn-sm acmeDownload" data-file="cert"><i class="fas fa-file"></i> {{Certificat seul}}</a>
									<a class="btn btn-default btn-sm acmeDownload" data-file="chain"><i class="fas fa-link"></i> {{Chaîne}}</a>
									<span class="help-block" style="margin:4px 0 0 0;">{{Les actions utilisent la configuration enregistrée : sauvegardez avant. « Tester (staging) » fait une émission complète auprès du serveur de test de Let's Encrypt, sans limite de taux et sans rien installer : à faire avant la première vraie demande. Les fichiers PEM servent à un proxy inverse, un NAS ou une configuration manuelle.}}</span>
								</div>
							</div>
						</fieldset>

						<fieldset>
							<legend><i class="fas fa-info-circle"></i> {{État du certificat}}</legend>
							<div id="div_acmeDisabled" class="alert alert-warning" style="display:none;"><i class="fas fa-exclamation-triangle"></i> {{Équipement désactivé : les boutons fonctionnent, mais le renouvellement automatique et les alertes quotidiennes l'ignorent. Cochez « Activer » puis sauvegardez.}}</div>
							<div id="div_acmeCert"><div class="alert alert-info">{{Chargement…}}</div></div>
							<div id="div_acmeTest"></div>
						</fieldset>

						<fieldset>
							<legend><i class="fas fa-tasks"></i> {{Tâche en cours}}</legend>
							<div id="div_acmeJobState"><span class="label label-default">{{Aucune tâche}}</span></div>
							<pre id="pre_acmeJobLog" class="acme-joblog" style="display:none;"></pre>
						</fieldset>
					</form>
				</div>
			</div>

			<!-- ======================== NOTIFICATIONS ======================= -->
			<div role="tabpanel" class="tab-pane" id="notifytab">
				<br>
				<div class="col-xs-12">
					<div class="alert alert-info">
						{{Let's Encrypt n'envoie plus d'e-mail avant l'expiration d'un certificat : c'est le plugin qui prévient. Le centre de messages de Jeedom est toujours alimenté ; ajoutez ici les commandes qui doivent vous prévenir autrement : mail, Telegram, SMS, notification de l'application mobile, scénario…}}
						<br>{{Pour chaque action, cochez les événements qui la déclenchent. Un titre ou un message laissé vide est rempli automatiquement.}}
						<br>{{Étiquettes utilisables dans les options :}} <code>#equipement#</code> <code>#domaines#</code> <code>#jours#</code> <code>#expiration#</code> <code>#evenement#</code> <code>#message#</code>
						<br>{{L'alerte d'expiration part chaque jour dès que le certificat expire dans moins de jours que le seuil « Alerter avant l'expiration » de la configuration du plugin, tant qu'il n'est pas renouvelé.}}
					</div>
					<div style="margin-bottom:10px;">
						<a class="btn btn-sm btn-success" id="bt_acmeAddNotify"><i class="fas fa-plus-circle"></i> {{Ajouter une action}}</a>
						<a class="btn btn-sm btn-primary" id="bt_acmeTestNotify" title="{{Exécute toutes les actions enregistrées, quels que soient les événements cochés. Sauvegardez d'abord.}}"><i class="fas fa-paper-plane"></i> {{Tester les notifications}}</a>
					</div>
					<div id="div_acmeNotify"></div>
					<div id="div_acmeNotifyResult"></div>
				</div>
			</div>

			<!-- ========================== COMMANDES ========================= -->
			<div role="tabpanel" class="tab-pane" id="commandtab">
				<br>
				<div class="col-xs-12">
					<table id="table_cmd" class="table table-bordered table-condensed">
						<thead>
							<tr>
								<th style="width:250px;">{{Nom}}</th>
								<th style="width:120px;">{{Type}}</th>
								<th>{{Paramètres}}</th>
								<th style="width:120px;">{{Actions}}</th>
							</tr>
						</thead>
						<tbody></tbody>
					</table>
				</div>
			</div>
		</div>
	</div>
</div>

<?php include_file('desktop', 'acme', 'css', 'acme'); ?>
<?php include_file('desktop', 'acme', 'js', 'acme'); ?>
<?php include_file('core', 'plugin.template', 'js'); ?>

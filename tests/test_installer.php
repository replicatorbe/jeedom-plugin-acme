<?php
/* Test de acmeInstaller — plugin Jeedom acme. Auteur : sMug (Jérôme Fafchamps).
 *
 * Lancé par tests/test_webserver.sh, qui prépare une racine factice et de faux
 * binaires en tête du PATH, et passe par l'environnement :
 *   ACME_TEST_ROOT, ACME_TEST_CERT, ACME_TEST_KEY, ACME_TEST_OTHER
 * Aucune dépendance au cœur de Jeedom. Sortie : lignes « ok … » / « ÉCHEC … ».
 */

require_once __DIR__ . '/../core/class/acmeInstaller.class.php';

$root = getenv('ACME_TEST_ROOT');
$cert = file_get_contents(getenv('ACME_TEST_CERT'));
$key = file_get_contents(getenv('ACME_TEST_KEY'));
$other = file_get_contents(getenv('ACME_TEST_OTHER'));
$failures = 0;

function check(string $desc, bool $cond): void {
    global $failures;
    echo ($cond ? 'ok ' : 'ÉCHEC ') . $desc . "\n";
    if (!$cond) {
        $failures++;
    }
}

$logs = array();
$logger = function (string $level, string $message) use (&$logs) {
    $logs[] = array($level, $message);
};

// Fichiers temporaires présents avant, pour vérifier qu'aucun ne reste.
$tmpBefore = glob(sys_get_temp_dir() . '/acme*') ?: array();

$inst = new acmeInstaller($logger, '');
$inst->setEnvironment(array('ACME_ROOT' => $root, 'ACME_DRYRUN' => '1'));

$d = $inst->detect();
check('detect : layout debian, apache, supported=1', ($d['layout'] ?? '') === 'debian' && ($d['webserver'] ?? '') === 'apache' && ($d['supported'] ?? '') === '1');

$r = $inst->install('jeedom.example.com', $cert, $key, array('port' => 443, 'redirect' => true));
check('install (dry-run) : ok', $r['ok'] === true);
check('install (dry-run) : data mode=auto, dryrun=1', ($r['data']['mode'] ?? '') === 'auto' && ($r['data']['dryrun'] ?? '') === '1');
check('install (dry-run) : output = messages lisibles', strpos($r['output'], 'Installation du certificat') !== false);
check('install (dry-run) : rien écrit dans la racine', !file_exists($root . '/etc/ssl/jeedom-acme'));
$tmpAfter = glob(sys_get_temp_dir() . '/acme*') ?: array();
check('fichiers PEM temporaires supprimés', count(array_diff($tmpAfter, $tmpBefore)) === 0);
$leak = false;
foreach ($logs as $l) {
    if (strpos($l[1], 'PRIVATE KEY') !== false) {
        $leak = true;
    }
}
check('aucune clé privée dans le journal', !$leak);
check('journal : commande en debug avec sh et arguments protégés', (bool) preg_grep("/^Commande : env 'ACME_ROOT=.*' sh '.*acme_webserver\\.sh' 'install' '--domain' 'jeedom\\.example\\.com'/", array_column($logs, 1)));

$r = $inst->install('jeedom.example.com', $cert, $other);
check('clé ≠ certificat : refus côté PHP, sans lancer le script', $r['ok'] === false && strpos($r['output'], 'ne correspond pas') !== false);

$r = $inst->install("x'; touch /tmp/acme-pwned; '", $cert, $key);
check('domaine hostile : refus du script (code 2), pas d\'injection', $r['ok'] === false && $r['code'] === 2 && !file_exists('/tmp/acme-pwned'));

// Noms du certificat : nom principal et alias.
check('resolveNames : sans liste, domaine tel quel', acmeInstaller::resolveNames('Jeedom.Example.com', array()) === array('jeedom.example.com', array()));
check('resolveNames : nom nu couvert → principal nu, joker en alias', acmeInstaller::resolveNames('example.com', array('*.example.com', 'EXAMPLE.com', 'example.com')) === array('example.com', array('*.example.com')));
check('resolveNames : nom nu non couvert → principal joker, pas d\'alias nu', acmeInstaller::resolveNames('example.com', array('*.example.com', 'www.example.com')) === array('*.example.com', array('www.example.com')));
check('resolveNames : principal passé avec « *. »', acmeInstaller::resolveNames('*.example.com', array('*.example.com')) === array('*.example.com', array()));
check('resolveNames : nom non chaîne → null', acmeInstaller::resolveNames('example.com', array(array('x'))) === null);
check('certNames : certificat sans SAN → aucun nom', acmeInstaller::certNames($cert) === array());

$logs = array();
$r = $inst->install('jeedom.example.com', $cert, $key, array('aliases' => array('jeedom.example.com', 'www.example.com', '*.example.com'), 'force_port' => true, 'port' => 8443));
check('install aliases (dry-run) : ok, data aliases', $r['ok'] === true && ($r['data']['aliases'] ?? '') === 'www.example.com *.example.com');
check('install aliases : --alias répété, --force-port transmis', (bool) preg_grep("/'--alias' 'www\\.example\\.com' '--alias' '\\*\\.example\\.com' '--force-port'$/", array_column($logs, 1)));
$r = $inst->install('jeedom.example.com', $cert, $key, array('aliases' => array("www.example.com\nSSLEngine off")));
check('alias avec retour à la ligne : refus du script (code 2)', $r['ok'] === false && $r['code'] === 2);
$r = $inst->install('jeedom.example.com', $cert, $key, array('aliases' => 'www.example.com'));
check('aliases non tableau : refus (code 2)', $r['ok'] === false && $r['code'] === 2);
$sanCert = file_get_contents(getenv('ACME_TEST_SANCERT'));
$sanKey = file_get_contents(getenv('ACME_TEST_SANKEY'));
check('certNames : noms SAN lus', acmeInstaller::certNames($sanCert) === array('*.example.com', 'www.example.com'));
$logs = array();
$r = $inst->install('example.com', $sanCert, $sanKey);
check('sans option aliases : noms lus dans le certificat, nom nu non couvert → --domain joker', $r['ok'] === true && (bool) preg_grep("/'--domain' '\\*\\.example\\.com'.*'--alias' 'www\\.example\\.com'$/", array_column($logs, 1)));

// Installation réelle dans la racine factice (sans dry-run).
$inst->setEnvironment(array('ACME_ROOT' => $root));
$r = $inst->install('jeedom.example.com', $cert, $key);
$k = $root . '/etc/ssl/jeedom-acme/jeedom.example.com/privkey.pem';
check('install (ACME_ROOT) : ok', $r['ok'] === true);
check('install (ACME_ROOT) : clé copiée en 0600', file_exists($k) && (fileperms($k) & 0777) === 0600);

$s = $inst->status();
check('status : installed=1, domaine', $s['ok'] && ($s['data']['installed'] ?? '') === '1' && ($s['data']['domain'] ?? '') === 'jeedom.example.com');
check('status : date d\'expiration', ($s['data']['cert_not_after'] ?? '') !== '');

$r = $inst->reload();
check('reload : ok', $r['ok'] === true);

$r = $inst->uninstall();
check('uninstall : ok, removed=1', $r['ok'] === true && ($r['data']['removed'] ?? '') === '1' && !file_exists($k));

check('parseOutput ignore les lignes non cle=valeur', acmeInstaller::parseOutput("a=1\nbruit\nb_c=x=y\n") === array('a' => '1', 'b_c' => 'x=y'));

exit($failures > 0 ? 1 : 0);

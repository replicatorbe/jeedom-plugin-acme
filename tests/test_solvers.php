<?php
/* This file is part of the Jeedom acme plugin.
 * Auteur : sMug (Jérôme Fafchamps) — Licence AGPL.
 *
 * Tests des solveurs (M2), en ligne de commande, hors de Jeedom :
 *   php tests/test_solvers.php            (tests réseau compris)
 *   php tests/test_solvers.php --offline  (sans les tests DNS réels)
 */

$root = dirname(__DIR__);
if (is_file($root . '/core/class/acmeClient.class.php')) {
    require_once $root . '/core/class/acmeClient.class.php';
}
if (!class_exists('acmeException', false)) {
    class acmeException extends Exception {
        public function getProblem(): array {
            return array();
        }
    }
}
require_once $root . '/core/class/acmeSolver.class.php';
require_once $root . '/core/class/acmeDns.class.php';

$offline = in_array('--offline', $argv, true);
$failures = 0;
$passes = 0;

function check(string $label, bool $ok, string $detail = ''): void {
    global $failures, $passes;
    if ($ok) {
        $passes++;
        echo "  OK    $label\n";
    } else {
        $failures++;
        echo "  ÉCHEC $label" . ($detail !== '' ? " — $detail" : '') . "\n";
    }
}

function section(string $title): void {
    echo "\n== $title ==\n";
}

$logs = array();
$logger = function (string $level, string $message) use (&$logs) {
    $logs[] = array($level, $message);
};

function rrmdir(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    foreach (array_diff(scandir($dir), array('.', '..')) as $e) {
        $p = $dir . '/' . $e;
        is_dir($p) && !is_link($p) ? rrmdir($p) : unlink($p);
    }
    rmdir($dir);
}

/* ------------------------------------------------------------------ */
section('HTTP-01');

/* Solveur dont le transport HTTP est simulé (pas de réseau). */
class testSolverHttp extends acmeSolverHttp {
    public $calls = array();
    public $responses = array();
    protected function httpGet(string $url, array $headers): array {
        $this->calls[] = array($url, $headers);
        $r = array_shift($this->responses);
        return $r !== null ? $r : array('code' => 0, 'body' => '', 'error' => 'simulé');
    }
}

$webroot = sys_get_temp_dir() . '/acme-test-' . bin2hex(random_bytes(4));
mkdir($webroot);
$token = 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA';
$keyAuth = $token . '.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI';

$http = new testSolverHttp($webroot);
$http->setLogger($logger);
check('getType = http-01', $http->getType() === 'http-01');
$http->prepare('jeedom.example.org', $token, $keyAuth);
$file = $webroot . '/.well-known/acme-challenge/' . $token;
check('fichier de défi écrit', is_file($file));
check('contenu = keyAuthorization', is_file($file) && file_get_contents($file) === $keyAuth);
check('.htaccess posé dans acme-challenge', is_file($webroot . '/.well-known/acme-challenge/.htaccess'));
check('.htaccess rouvre l\'accès', strpos((string) @file_get_contents($webroot . '/.well-known/acme-challenge/.htaccess'), 'Allow from all') !== false);
check('aucun fichier temporaire laissé', count(glob($webroot . '/.well-known/acme-challenge/.*.tmp')) == 0);

// Deuxième défi (autre domaine) dans les mêmes dossiers.
$token2 = 'abcDEF_123-xyz';
$http->prepare('jeedom.example.org', $token2, $token2 . '.thumb');
check('deuxième fichier écrit', is_file($webroot . '/.well-known/acme-challenge/' . $token2));

// Jetons malveillants.
foreach (array('../../etc/passwd', 'a/b', 'abc.def', '', "abc\0def", 'abc def', '..') as $bad) {
    $refused = false;
    try {
        $http->prepare('jeedom.example.org', $bad, 'x.y');
    } catch (acmeException $e) {
        $refused = true;
    }
    check('jeton refusé : ' . json_encode($bad), $refused);
}
$refused = false;
try {
    $http->prepare('jeedom.example.org', 'abc', "abc.x\n<?php");
} catch (acmeException $e) {
    $refused = true;
}
check('keyAuthorization malveillante refusée', $refused);

// Auto-vérification : public KO, local OK → avertissement, pas d'exception.
$http->responses = array(
    array('code' => 0, 'body' => '', 'error' => 'Connection timed out'),
    array('code' => 200, 'body' => $keyAuth . "\n", 'error' => ''),
    array('code' => 200, 'body' => $token2 . '.thumb', 'error' => ''),
);
$logs = array();
$threw = false;
try {
    $http->waitReady();
} catch (Throwable $e) {
    $threw = true;
}
check('waitReady ne lève pas', !$threw);
check('waitReady essaie le nom public puis 127.0.0.1 avec Host',
    count($http->calls) == 3
    && $http->calls[0][0] === 'http://jeedom.example.org/.well-known/acme-challenge/' . $token
    && $http->calls[1][0] === 'http://127.0.0.1/.well-known/acme-challenge/' . $token
    && $http->calls[1][1] === array('Host: jeedom.example.org'));
$warn = array_filter($logs, function ($l) { return $l[0] === 'warning'; });
check('avertissement journalisé si le nom public échoue', count($warn) == 1);

// Nettoyage : fichiers, .htaccess et dossiers créés disparaissent.
$http->cleanup();
check('fichier retiré', !file_exists($file));
check('dossier acme-challenge retiré', !is_dir($webroot . '/.well-known/acme-challenge'));
check('dossier .well-known retiré', !is_dir($webroot . '/.well-known'));
check('racine web conservée', is_dir($webroot));

// Dossiers préexistants : conservés, .htaccess préexistant intact.
mkdir($webroot . '/.well-known/acme-challenge', 0755, true);
file_put_contents($webroot . '/.well-known/acme-challenge/.htaccess', "# existant\n");
file_put_contents($webroot . '/.well-known/security.txt', "Contact: x\n");
$http2 = new testSolverHttp($webroot);
$http2->prepare('jeedom.example.org', $token, $keyAuth);
$http2->cleanup();
check('dossiers préexistants conservés', is_dir($webroot . '/.well-known/acme-challenge'));
check('.htaccess préexistant intact', file_get_contents($webroot . '/.well-known/acme-challenge/.htaccess') === "# existant\n");
check('fichier de défi retiré (dossier préexistant)', !file_exists($webroot . '/.well-known/acme-challenge/' . $token));


// Essai interrompu : .htaccess du plugin repris, jetons orphelins de plus d'une heure retirés.
$dir = $webroot . '/.well-known/acme-challenge';
file_put_contents($dir . '/.htaccess', acmeSolverHttp::HTACCESS_MARKER . "\n# ancienne version\n");
$oldTok = str_repeat('A', 42) . 'b';
$recentTok = str_repeat('C', 42) . 'd';
$oldTmp = '.' . str_repeat('E', 43) . '.0123abcd.tmp';
file_put_contents($dir . '/' . $oldTok, 'x');
file_put_contents($dir . '/' . $recentTok, 'x');
file_put_contents($dir . '/' . $oldTmp, 'x');
file_put_contents($dir . '/autre-fichier', 'x');
touch($dir . '/' . $oldTok, time() - 7200);
touch($dir . '/' . $oldTmp, time() - 7200);
touch($dir . '/autre-fichier', time() - 7200);
$logs = array();
$http3 = new testSolverHttp($webroot);
$http3->setLogger($logger);
$http3->prepare('jeedom.example.org', $token, $keyAuth);
check('.htaccess du plugin repris et remis à jour', strpos(file_get_contents($dir . '/.htaccess'), 'Allow from all') !== false);
check('jeton orphelin de plus d\'une heure retiré', !file_exists($dir . '/' . $oldTok));
check('fichier temporaire orphelin retiré', !file_exists($dir . '/' . $oldTmp));
check('jeton récent conservé', file_exists($dir . '/' . $recentTok));
check('fichier étranger conservé', file_exists($dir . '/autre-fichier'));
check('retrait des orphelins journalisé', count(array_filter($logs, function ($l) { return strpos($l[1], 'orphelin') !== false; })) == 2);
$http3->cleanup();
check('.htaccess repris retiré au nettoyage', !file_exists($dir . '/.htaccess'));
unlink($dir . '/' . $recentTok);
unlink($dir . '/autre-fichier');

// Racine inexistante.
$refused = false;
try {
    (new acmeSolverHttp($webroot . '/absent'))->prepare('a.b', 'tok', 'tok.x');
} catch (acmeException $e) {
    $refused = true;
}
check('racine web absente → acmeException', $refused);
rrmdir($webroot);

/* ------------------------------------------------------------------ */
section('DNS-01 : calcul');

// Vecteur calculé indépendamment :
//   printf '%s' "$keyAuth" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
check('valeur TXT = vecteur connu',
    acmeSolverDns::recordValue($keyAuth) === 'lCM7cZyQXcVHK2nnW3jjAhNT3Fvm18UN-kWZZknKoYM',
    acmeSolverDns::recordValue($keyAuth));
check('pas de remplissage « = »', strpos(acmeSolverDns::recordValue('x'), '=') === false);
check('nom TXT', acmeSolverDns::recordName('Jeedom.Example.org.') === '_acme-challenge.jeedom.example.org');
check('nom TXT d\'un wildcard (défensif)', acmeSolverDns::recordName('*.example.org') === '_acme-challenge.example.org');

/* ------------------------------------------------------------------ */
section('DNS-01 : solveur avec faux fournisseur');

class fakeDnsProvider implements acmeDnsProvider {
    public $calls = array();
    public $zone = array();          // fqdn => liste de valeurs
    public $failRemove = false;
    public $failAddOn = null;         // valeur qui fait échouer addTxt
    public $onlyZones = null;         // zones accessibles (null = toutes)
    public function __construct(array $config, ?callable $logger = null) {
    }
    public static function getLabel(): string {
        return 'Faux';
    }
    public static function getFields(): array {
        return array();
    }
    public function test(): string {
        return 'ok';
    }
    public function addTxt(string $fqdn, string $value): void {
        $this->calls[] = array('add', $fqdn, $value);
        if ($this->failAddOn === $value) {
            throw new acmeException('échec simulé');
        }
        if ($this->onlyZones !== null) {
            $ok = false;
            foreach ($this->onlyZones as $z) {
                $ok = $ok || substr($fqdn, -strlen($z) - 1) === '.' . $z;
            }
            if (!$ok) {
                throw new acmeException('Aucune zone DNS ne correspond à ' . $fqdn);
            }
        }
        $this->zone[$fqdn][] = $value;
    }
    public function removeTxt(string $fqdn, string $value): void {
        $this->calls[] = array('remove', $fqdn, $value);
        if ($this->failRemove) {
            throw new acmeException('retrait impossible (simulé)');
        }
        $this->zone[$fqdn] = array_values(array_diff(isset($this->zone[$fqdn]) ? $this->zone[$fqdn] : array(), array($value)));
    }
    public function commit(): void {
        $this->calls[] = array('commit');
    }
}

/* Fournisseur complet : méthodes facultatives listTxt() et expectedNameServers(). */
class fakeDnsProviderFull extends fakeDnsProvider {
    public $nsSuffixes = array('ovh.net', 'anycast.me');
    public static function getLabel(): string {
        return 'FauxDNS';
    }
    public function listTxt(string $fqdn): array {
        $this->calls[] = array('list', $fqdn);
        return isset($this->zone[$fqdn]) ? $this->zone[$fqdn] : array();
    }
    public function expectedNameServers(): array {
        return $this->nsSuffixes;
    }
    public function removeTxt(string $fqdn, string $value): void {
        $this->calls[] = array('remove', $fqdn, $value);
        $keep = array();
        foreach (isset($this->zone[$fqdn]) ? $this->zone[$fqdn] : array() as $v) {
            if (trim($v, '"') !== $value) {
                $keep[] = $v;
            }
        }
        $this->zone[$fqdn] = $keep;
    }
}

/* Solveur sans réseau ni attente réelle ; horloge simulée. */
class testSolverDns extends acmeSolverDns {
    public $visibleAfter = 0;         // nombre de vérifications avant visibilité
    public $state = 'missing';        // état rendu avant visibilité
    public $statusFn = null;          // function ($fqdn, $value, $allowDoh, $solver): array
    public $real = false;             // vraie vérification (acmeDnsCheck, crochets simulés)
    public $checks = 0;
    public $checked = array();        // noms vérifiés
    public $allowDohSeen = array();
    public $slept = 0;
    public $clock = 1000;
    public $cnames = array();         // nom => cible du CNAME
    public $ns = null;                // ['zone' => ..., 'hosts' => [...]]
    public $nsCalls = 0;
    protected function checkStatus(string $fqdn, string $value, bool $allowDoh): array {
        $this->checks++;
        $this->checked[] = $fqdn;
        $this->allowDohSeen[] = $allowDoh;
        if ($this->real) {
            return parent::checkStatus($fqdn, $value, $allowDoh);
        }
        if ($this->statusFn !== null) {
            return call_user_func($this->statusFn, $fqdn, $value, $allowDoh, $this);
        }
        $visible = $this->checks > $this->visibleAfter;
        return array('state' => $visible ? 'visible' : $this->state, 'method' => 'direct', 'zone' => 'example.org',
            'name' => $fqdn, 'servers' => array('dns14.ovh.net (192.0.2.14) : nom inexistant (NXDOMAIN)',
                'ns14.ovh.net (192.0.2.15) : pas de réponse'),
            'deferred' => false, 'details' => 'simulé');
    }
    protected function now(): int {
        return $this->clock;
    }
    protected function sleepSeconds(int $seconds): void {
        $this->slept += $seconds;
        $this->clock += $seconds;
    }
    protected function resolveTarget(string $name): ?string {
        return isset($this->cnames[$name]) ? $this->cnames[$name] : null;
    }
    protected function nameServers(string $fqdn): array {
        $this->nsCalls++;
        return $this->ns !== null ? $this->ns : array('zone' => null, 'hosts' => array());
    }
}

function levelCount(array $logs, string $level): int {
    return count(array_filter($logs, function ($l) use ($level) { return $l[0] === $level; }));
}

$fake = new fakeDnsProvider(array());
$dns = new testSolverDns($fake, array('pollInterval' => 5, 'extraDelay' => 7));
$dns->setLogger($logger);
check('getType = dns-01', $dns->getType() === 'dns-01');
$ka1 = 'tokenA.thumb';
$ka2 = 'tokenB.thumb';
$dns->prepare('example.org', 'tokenA', $ka1);       // domaine
$dns->prepare('example.org', 'tokenB', $ka2);       // wildcard (*.example.org → example.org)
$dns->prepare('example.org', 'tokenA', $ka1);       // doublon ignoré
$fq = '_acme-challenge.example.org';
check('deux valeurs coexistent sur le même fqdn',
    isset($fake->zone[$fq]) && count($fake->zone[$fq]) == 2
    && in_array(acmeSolverDns::recordValue($ka1), $fake->zone[$fq], true)
    && in_array(acmeSolverDns::recordValue($ka2), $fake->zone[$fq], true));
check('doublon non reposé', count($dns->getRecords()) == 2);
$dns->visibleAfter = 1;
$dns->waitReady();
check('commit avant la vérification', $fake->calls[2] === array('commit'));
check('boucle de propagation puis délai supplémentaire', $dns->slept == 5 + 7, 'dormi ' . $dns->slept . ' s');
$dns->cleanup();
$removes = array_filter($fake->calls, function ($c) { return $c[0] === 'remove'; });
check('cleanup retire les deux valeurs', count($removes) == 2 && count($fake->zone[$fq]) == 0);
check('cleanup republie la zone', end($fake->calls) === array('commit'));

// Délai dépassé, TXT absent des serveurs d'autorité : exception utile, pas de validation.
$fake = new fakeDnsProvider(array());
$dns = new testSolverDns($fake, array('propagationTimeout' => 30, 'pollInterval' => 10, 'extraDelay' => 5));
$dns->visibleAfter = 1000;
$logs = array();
$dns->setLogger($logger);
$dns->prepare('jeedom.example.org', 't', 't.k');
$msg = null;
try {
    $dns->waitReady();
} catch (acmeException $e) {
    $msg = $e->getMessage();
}
check('délai dépassé, TXT absent : acmeException', $msg !== null);
check('message : serveurs interrogés et réponses', $msg !== null && strpos($msg, 'dns14.ovh.net (192.0.2.14) : nom inexistant') !== false
    && strpos($msg, 'ns14.ovh.net') !== false && strpos($msg, '_acme-challenge.jeedom.example.org') !== false, (string) $msg);
check('message : conseils (délai, serveurs DNS du fournisseur)', $msg !== null && strpos($msg, 'augmentez le délai de propagation') !== false
    && strpos($msg, 'zone example.org') !== false && strpos($msg, 'Faux') !== false, (string) $msg);
check('délai dépassé : attente bornée au délai, sans délai supplémentaire', $dns->slept == 30, 'dormi ' . $dns->slept . ' s');
$dns->cleanup();
check('cleanup après l\'exception : TXT retiré', count(array_filter($fake->calls, function ($c) { return $c[0] === 'remove'; })) == 1);

// Absent sur un seul serveur d'autorité (propagation partielle) : exception aussi.
$fake = new fakeDnsProvider(array());
$dns = new testSolverDns($fake, array('propagationTimeout' => 0));
$dns->statusFn = function ($fqdn, $value, $allowDoh) {
    return array('state' => 'missing', 'method' => 'direct', 'zone' => 'example.org', 'name' => $fqdn,
        'servers' => array('dns14.ovh.net (192.0.2.14) : valeur présente', 'ns14.ovh.net (192.0.2.15) : aucun TXT sur ce nom'),
        'deferred' => false, 'details' => '1/2');
};
$dns->prepare('jeedom.example.org', 't', 't.k');
$msg = null;
try {
    $dns->waitReady();
} catch (acmeException $e) {
    $msg = $e->getMessage();
}
check('propagation partielle au délai : acmeException', $msg !== null && strpos($msg, 'ns14.ovh.net (192.0.2.15) : aucun TXT') !== false, (string) $msg);

// Délai dépassé, vérification impossible : avertissement, délai de sécurité de 60 s, on continue.
$fake = new fakeDnsProvider(array());
$dns = new testSolverDns($fake, array('propagationTimeout' => 20, 'pollInterval' => 10));
$dns->visibleAfter = 1000;
$dns->state = 'unknown';
$logs = array();
$dns->setLogger($logger);
$dns->prepare('jeedom.example.org', 't', 't.k');
$threw = false;
try {
    $dns->waitReady();
} catch (Throwable $e) {
    $threw = true;
}
check('impossible à vérifier : pas d\'exception', !$threw);
check('impossible à vérifier : avertissement', levelCount($logs, 'warning') == 1);
check('impossible à vérifier : délai de sécurité de 60 s', $dns->slept == 20 + 60, 'dormi ' . $dns->slept . ' s');
// … remplacé par extraDelay s'il est configuré.
$dns = new testSolverDns(new fakeDnsProvider(array()), array('propagationTimeout' => 0, 'extraDelay' => 25));
$dns->visibleAfter = 1000;
$dns->state = 'unknown';
$dns->prepare('jeedom.example.org', 't', 't.k');
$dns->waitReady();
check('impossible à vérifier avec extraDelay : extraDelay seul', $dns->slept == 25, 'dormi ' . $dns->slept . ' s');

// DoH nécessaire : pas d'interrogation avant 90 s après la publication.
$dns = new testSolverDns(new fakeDnsProvider(array()), array('propagationTimeout' => 300, 'pollInterval' => 10));
$dns->statusFn = function ($fqdn, $value, $allowDoh) {
    if (!$allowDoh) {
        return array('state' => 'unknown', 'method' => 'doh', 'zone' => null, 'name' => $fqdn, 'servers' => array(),
            'deferred' => true, 'details' => 'différé');
    }
    return array('state' => 'visible', 'method' => 'doh', 'zone' => null, 'name' => $fqdn, 'servers' => array(),
        'deferred' => false, 'details' => 'vu');
};
$dns->prepare('jeedom.example.org', 't', 't.k');
$dns->waitReady();
check('DoH : première interrogation différée à 90 s', $dns->allowDohSeen === array(false, true) && $dns->slept == 90,
    json_encode($dns->allowDohSeen) . ' dormi ' . $dns->slept);

// checkPropagation = false : aucune vérification.
$fake = new fakeDnsProvider(array());
$dns = new testSolverDns($fake, array('checkPropagation' => false));
$dns->prepare('jeedom.example.org', 't', 't.k');
$dns->waitReady();
check('checkPropagation=false : aucune vérification', $dns->checks == 0);

// Cleanup appelé même en erreur (déroulé d'acmeClient::issue()).
$fake = new fakeDnsProvider(array());
$fake->failAddOn = acmeSolverDns::recordValue('t2.k');
$dns = new testSolverDns($fake, array());
$logs = array();
$dns->setLogger($logger);
$threw = false;
try {
    try {
        $dns->prepare('a.example.org', 't1', 't1.k');
        $dns->prepare('b.example.org', 't2', 't2.k');
        $dns->waitReady();
    } finally {
        $dns->cleanup();
    }
} catch (acmeException $e) {
    $threw = true;
}
$removed = array();
foreach ($fake->calls as $c) {
    if ($c[0] === 'remove') {
        $removed[] = $c[1];
    }
}
check('erreur de addTxt propagée', $threw);
check('cleanup tente le retrait de tout, y compris l\'enregistrement en échec',
    $removed === array('_acme-challenge.a.example.org', '_acme-challenge.b.example.org'));

// Cleanup ne lève jamais, même si le fournisseur échoue.
$fake = new fakeDnsProvider(array());
$fake->failRemove = true;
$dns = new testSolverDns($fake, array());
$logs = array();
$dns->setLogger($logger);
$dns->prepare('a.example.org', 't1', 't1.k');
$threw = false;
try {
    $dns->cleanup();
} catch (Throwable $e) {
    $threw = true;
}
check('cleanup ne lève pas si removeTxt échoue', !$threw);
check('erreur de retrait journalisée', count(array_filter($logs, function ($l) { return $l[0] === 'error'; })) >= 1);


// CNAME de délégation : TXT posé sur la cible, vérification sur le nom d'origine.
$fake = new fakeDnsProvider(array());
$dns = new testSolverDns($fake, array());
$logs = array();
$dns->setLogger($logger);
$dns->cnames['_acme-challenge.jeedom.example.org'] = 'local.acme-deleg.example';
$dns->prepare('jeedom.example.org', 't', 't.k');
$dns->prepare('jeedom.example.org', 't2', 't2.k');     // wildcard : même nom, même cible
$adds = array_values(array_filter($fake->calls, function ($c) { return $c[0] === 'add'; }));
check('CNAME : TXT écrit sur la cible', count($adds) == 2 && $adds[0][1] === 'local.acme-deleg.example'
    && $adds[1][1] === 'local.acme-deleg.example', json_encode($fake->calls));
$dns->waitReady();
check('CNAME : vérification sur _acme-challenge.<domaine> (CNAME suivi)', $dns->checked[0] === '_acme-challenge.jeedom.example.org');
$dns->cleanup();
$rems = array_values(array_filter($fake->calls, function ($c) { return $c[0] === 'remove'; }));
check('CNAME : retrait sur la cible', count($rems) == 2 && $rems[0][1] === 'local.acme-deleg.example');

// Cible hors de portée du fournisseur : erreur claire.
$fake = new fakeDnsProvider(array());
$fake->onlyZones = array('example.org');
$dns = new testSolverDns($fake, array());
$dns->cnames['_acme-challenge.jeedom.example.org'] = 'x.autre.example';
$msg = null;
try {
    $dns->prepare('jeedom.example.org', 't', 't.k');
} catch (acmeException $e) {
    $msg = $e->getMessage();
}
check('CNAME vers une zone inaccessible : erreur claire', $msg !== null && strpos($msg, 'CNAME vers x.autre.example') !== false
    && strpos($msg, 'Aucune zone DNS') !== false, (string) $msg);

// TXT ACME orphelins d'un essai interrompu : retirés au premier prepare() pour ce nom.
$fq = '_acme-challenge.jeedom.example.org';
$orphan1 = str_repeat('a', 20) . '_' . str_repeat('B', 21) . '-';           // 43 caractères
$orphan2 = '"' . str_repeat('Z', 43) . '"';
$fake = new fakeDnsProviderFull(array());
$fake->zone[$fq] = array($orphan1, $orphan2, 'google-site-verification=abc', str_repeat('x', 42), str_repeat('y', 44));
$dns = new testSolverDns($fake, array());
$logs = array();
$dns->setLogger($logger);
$dns->prepare('jeedom.example.org', 't', 't.k');
$dns->prepare('jeedom.example.org', 't2', 't2.k');
$lists = array_filter($fake->calls, function ($c) { return $c[0] === 'list'; });
$rems = array_values(array_filter($fake->calls, function ($c) { return $c[0] === 'remove'; }));
check('orphelins : liste lue une seule fois par nom', count($lists) == 1);
check('orphelins : les deux valeurs ACME retirées (guillemets ôtés)', count($rems) == 2 && $rems[0][2] === $orphan1
    && $rems[1][2] === str_repeat('Z', 43), json_encode($rems));
check('orphelins : autres TXT conservés', in_array('google-site-verification=abc', $fake->zone[$fq], true)
    && in_array(str_repeat('x', 42), $fake->zone[$fq], true) && in_array(str_repeat('y', 44), $fake->zone[$fq], true));
check('orphelins : retrait avant l\'ajout des nouvelles valeurs', $fake->calls[1][0] === 'remove' && $fake->calls[3][0] === 'add');
check('orphelins : retrait journalisé', count(array_filter($logs, function ($l) { return strpos($l[1], 'orphelin') !== false; })) == 2);
$dns->cleanup();

// Orphelins retirés puis échec de addTxt : le retrait est quand même publié.
$fake = new fakeDnsProviderFull(array());
$fake->zone[$fq] = array($orphan1);
$fake->failAddOn = acmeSolverDns::recordValue('t.k');
$dns = new testSolverDns($fake, array());
try {
    $dns->prepare('jeedom.example.org', 't', 't.k');
} catch (acmeException $e) {
}
$dns->cleanup();
check('orphelins : cleanup publie la zone', end($fake->calls) === array('commit'));

// Fournisseur sans listTxt() : aucune recherche d'orphelins.
$fake = new fakeDnsProvider(array());
$dns = new testSolverDns($fake, array());
$dns->prepare('jeedom.example.org', 't', 't.k');
check('sans listTxt() : seulement addTxt', $fake->calls === array(array('add', $fq, acmeSolverDns::recordValue('t.k'))));

// Serveurs DNS de la zone étrangers au fournisseur : avertissement, une fois par zone.
$fake = new fakeDnsProviderFull(array());
$dns = new testSolverDns($fake, array());
$dns->ns = array('zone' => 'example.org', 'hosts' => array('ns1.autre-hebergeur.net', 'ns2.autre-hebergeur.net'));
$logs = array();
$dns->setLogger($logger);
$dns->prepare('jeedom.example.org', 't', 't.k');
$dns->prepare('www.example.org', 't3', 't3.k');
$nsWarn = array_filter($logs, function ($l) { return $l[0] === 'warning' && strpos($l[1], 'ne ressemblent pas') !== false; });
check('serveurs DNS étrangers : un avertissement', count($nsWarn) == 1, json_encode($logs));
check('serveurs DNS étrangers : message utile', count($nsWarn) == 1 && strpos(reset($nsWarn)[1], 'ns1.autre-hebergeur.net') !== false
    && strpos(reset($nsWarn)[1], 'FauxDNS') !== false);
$dns = new testSolverDns(new fakeDnsProviderFull(array()), array());
$dns->ns = array('zone' => 'example.org', 'hosts' => array('dns14.ovh.net', 'ns14.ovh.net'));
$logs = array();
$dns->setLogger($logger);
$dns->prepare('jeedom.example.org', 't', 't.k');
check('serveurs DNS du fournisseur : aucun avertissement', levelCount($logs, 'warning') == 0);
$dns = new testSolverDns(new fakeDnsProvider(array()), array());
$dns->prepare('jeedom.example.org', 't', 't.k');
check('fournisseur sans expectedNameServers() : pas de contrôle', $dns->nsCalls == 0);

/* ------------------------------------------------------------------ */
section('acmeDnsCheck : paquets DNS (hors ligne)');

$q = acmeDnsCheck::buildQuery(0x1234, '_acme-challenge.Jeedom.example.org', acmeDnsCheck::TYPE_TXT, false);
check('requête : en-tête (RD=0, 1 question)', substr($q, 0, 12) === pack('nnnnnn', 0x1234, 0, 1, 0, 0, 0));
check('requête : nom encodé', substr($q, 12, -4) === "\x0f_acme-challenge\x06jeedom\x07example\x03org\x00");

// Réponse forgée : question, CNAME (compressé) puis TXT en deux chaînes sur la cible.
$qname = "\x0f_acme-challenge\x06jeedom\x07example\x03org\x00";
$resp = pack('nnnnnn', 0x1234, 0x8400, 1, 2, 0, 0) . $qname . pack('nn', 16, 1);
// CNAME : _acme-challenge.jeedom.example.org → acme.example.org (« acme » + pointeur vers « example.org », offset 12+1+15+1+6 = 35)
$cnameRdata = "\x04acme" . pack('n', 0xC000 | 35);
$resp .= pack('n', 0xC00C) . pack('nnNn', 5, 1, 60, strlen($cnameRdata)) . $cnameRdata;
$cnameTargetOffset = strlen($resp) - strlen($cnameRdata);
$txtRdata = "\x05hello\x05world";
$resp .= pack('n', 0xC000 | $cnameTargetOffset) . pack('nnNn', 16, 1, 60, strlen($txtRdata)) . $txtRdata;
$parsed = acmeDnsCheck::parseResponse($resp, '_acme-challenge.jeedom.example.org');
check('analyse : AA, rcode 0', $parsed['aa'] && $parsed['rcode'] == 0);
check('analyse : CNAME suivi, TXT concaténé', $parsed['txt'] === array('helloworld') && $parsed['cname'] === null,
    json_encode($parsed));

// Même réponse sans le TXT : le CNAME doit être remonté.
$resp2 = pack('nnnnnn', 0x1234, 0x8400, 1, 1, 0, 0) . $qname . pack('nn', 16, 1)
    . pack('n', 0xC00C) . pack('nnNn', 5, 1, 60, strlen($cnameRdata)) . $cnameRdata;
$parsed = acmeDnsCheck::parseResponse($resp2, '_acme-challenge.jeedom.example.org');
check('analyse : cible CNAME remontée', $parsed['cname'] === 'acme.example.org', json_encode($parsed));

// Boucle de compression : refusée proprement.
$evil = pack('nnnnnn', 1, 0x8000, 1, 0, 0, 0) . pack('n', 0xC00C);
$refused = false;
try {
    acmeDnsCheck::parseResponse($evil, 'x');
} catch (acmeException $e) {
    $refused = true;
}
check('boucle de compression refusée', $refused);

check('TXT présentation « "a" "b" »', acmeDnsCheck::parseTxtPresentation('"abc" "def"') === 'abcdef');
check('TXT présentation échappements', acmeDnsCheck::parseTxtPresentation('"a\\"b\\065"') === 'a"bA');
check('TXT sans guillemets', acmeDnsCheck::parseTxtPresentation('v=spf1 -all') === 'v=spf1 -all');


/* ------------------------------------------------------------------ */
section('acmeDnsCheck : états (transport simulé)');

/* Zone example.org servie par dns14/ns14.ovh.net (IPv4 et IPv6), zone
 * acme-deleg.example pour la délégation par CNAME. */
$sim = array();
function simReset(): void {
    global $sim;
    $sim = array('txt' => array(), 'down' => array(), 'lagging' => array(), 'cname' => array(), 'queries' => array(),
        'doh' => array('cloudflare-dns.com' => null, 'dns.google' => null), 'dohCalls' => array(), 'sysCname' => array());
    acmeDnsCheck::reset();
    acmeDnsCheck::$mode = 'auto';
    acmeDnsCheck::$lookupHook = function ($name, $type) use (&$sim) {
        $ns = array('example.org' => array('dns14.ovh.net', 'ns14.ovh.net'), 'acme-deleg.example' => array('ns1.deleg.example'));
        $a = array('dns14.ovh.net' => '192.0.2.14', 'ns14.ovh.net' => '192.0.2.15', 'ns1.deleg.example' => '192.0.2.53');
        $aaaa = array('dns14.ovh.net' => '2001:db8::14', 'ns14.ovh.net' => '2001:db8::15');
        $out = array();
        if ($type == DNS_NS && isset($ns[$name])) {
            foreach ($ns[$name] as $h) {
                $out[] = array('host' => $name, 'type' => 'NS', 'target' => $h);
            }
        } elseif ($type == DNS_A && isset($a[$name])) {
            $out[] = array('host' => $name, 'type' => 'A', 'ip' => $a[$name]);
        } elseif ($type == DNS_AAAA && isset($aaaa[$name])) {
            $out[] = array('host' => $name, 'type' => 'AAAA', 'ipv6' => $aaaa[$name]);
        } elseif ($type == DNS_CNAME && isset($sim['sysCname'][$name])) {
            $out[] = array('host' => $name, 'type' => 'CNAME', 'target' => $sim['sysCname'][$name]);
        }
        return $out;
    };
    acmeDnsCheck::$queryHook = function ($ip, $name, $type) use (&$sim) {
        $sim['queries'][] = $ip . ' ' . $name . ' ' . $type;
        if (in_array($ip, $sim['down'], true)) {
            return null;
        }
        if (isset($sim['cname'][$name])) {
            return array('rcode' => 0, 'txt' => array(), 'cname' => $sim['cname'][$name]);
        }
        $exists = isset($sim['txt'][$name]);
        if ($type != acmeDnsCheck::TYPE_TXT || in_array($ip, $sim['lagging'], true) || !$exists) {
            return array('rcode' => $exists ? 0 : 3, 'txt' => array(), 'cname' => null);
        }
        return array('rcode' => 0, 'txt' => $sim['txt'][$name], 'cname' => null);
    };
    acmeDnsCheck::$dohHook = function ($endpoint, $name) use (&$sim) {
        $host = parse_url($endpoint, PHP_URL_HOST);
        $sim['dohCalls'][] = $host;
        return $sim['doh'][$host];
    };
}

$fq = '_acme-challenge.jeedom.example.org';
$val = str_repeat('v', 43);

simReset();
$sim['txt'][$fq] = array('autre', $val);
$st = acmeDnsCheck::txtStatus($fq, $val);
check('visible sur tous les serveurs (IPv4 et IPv6)', $st['state'] === 'visible' && $st['method'] === 'direct'
    && $st['zone'] === 'example.org' && count($sim['queries']) == 4, json_encode($st));
check('détail par serveur, avec son nom', in_array('dns14.ovh.net (192.0.2.14) : valeur présente', $st['servers'], true)
    && in_array('ns14.ovh.net (2001:db8::15) : valeur présente', $st['servers'], true), json_encode($st['servers']));
check('txtVisible (contrat) : vrai', acmeDnsCheck::txtVisible($fq, $val));
check('authoritativeNameServers', acmeDnsCheck::authoritativeNameServers($fq) === array('dns14.ovh.net', 'ns14.ovh.net'));

simReset();
$sim['txt'][$fq] = array($val);
$sim['lagging'] = array('192.0.2.15', '2001:db8::15');
$st = acmeDnsCheck::txtStatus($fq, $val);
check('absent d\'un serveur d\'autorité → missing', $st['state'] === 'missing'
    && in_array('ns14.ovh.net (192.0.2.15) : aucun TXT sur ce nom', $st['servers'], true), json_encode($st));
check('txtVisible (contrat) : faux', !acmeDnsCheck::txtVisible($fq, $val));

simReset();
$sim['txt'][$fq] = array('google-site-verification=abc');
$st = acmeDnsCheck::txtStatus($fq, $val);
check('autre valeur seulement → missing, TXT présents cités', $st['state'] === 'missing'
    && strpos(implode(' ', $st['servers']), 'google-site-verification=abc') !== false, json_encode($st['servers']));

simReset();
$st = acmeDnsCheck::txtStatus($fq, $val);
check('nom inexistant → missing (NXDOMAIN)', $st['state'] === 'missing'
    && strpos(implode(' ', $st['servers']), 'NXDOMAIN') !== false);

// Machine IPv6 seulement : les adresses IPv4 ne répondent pas.
simReset();
$sim['txt'][$fq] = array($val);
$sim['down'] = array('192.0.2.14', '192.0.2.15');
$st = acmeDnsCheck::txtStatus($fq, $val);
check('IPv6 seulement : visible via les adresses IPv6', $st['state'] === 'visible', json_encode($st));
$sim['queries'] = array();
acmeDnsCheck::txtStatus($fq, $val);
check('IPv6 seulement : IPv4 ignorée ensuite', count($sim['queries']) == 2
    && strpos($sim['queries'][0], '2001:db8::') === 0, json_encode($sim['queries']));

// Aucun serveur d'autorité joignable : repli DoH.
simReset();
$sim['down'] = array('192.0.2.14', '192.0.2.15', '2001:db8::14', '2001:db8::15');
$st = acmeDnsCheck::txtStatus($fq, $val, null, false);
check('injoignables, DoH pas encore autorisé → unknown différé, sans appel DoH', $st['state'] === 'unknown'
    && $st['deferred'] === true && count($sim['dohCalls']) == 0, json_encode($st));
$sim['queries'] = array();
$sim['doh']['cloudflare-dns.com'] = array();
$st = acmeDnsCheck::txtStatus($fq, $val);
check('DoH ne voit pas la valeur → unknown (jamais missing)', $st['state'] === 'unknown' && $st['method'] === 'doh'
    && strpos($st['details'], 'cache') !== false, json_encode($st));
check('serveurs injoignables : plus interrogés ensuite', count($sim['queries']) == 0);
$sim['doh']['cloudflare-dns.com'] = array($val);
$st = acmeDnsCheck::txtStatus($fq, $val);
check('DoH voit la valeur → visible', $st['state'] === 'visible' && $st['method'] === 'doh');
$sim['doh']['cloudflare-dns.com'] = null;
$sim['doh']['dns.google'] = null;
$st = acmeDnsCheck::txtStatus($fq, $val);
check('ni autorité ni DoH → unknown « impossible à vérifier »', $st['state'] === 'unknown' && $st['method'] === 'none'
    && strpos($st['details'], 'impossible') !== false, json_encode($st));
simReset();
acmeDnsCheck::$mode = 'direct';
$sim['down'] = array('192.0.2.14', '192.0.2.15', '2001:db8::14', '2001:db8::15');
$st = acmeDnsCheck::txtStatus($fq, $val);
check('mode direct, injoignables → unknown', $st['state'] === 'unknown' && count($sim['dohCalls']) == 0);

// CNAME de délégation.
simReset();
$sim['cname'][$fq] = 'local.acme-deleg.example';
$sim['txt']['local.acme-deleg.example'] = array($val);
check('cnameTarget : cible via les serveurs d\'autorité', acmeDnsCheck::cnameTarget($fq) === 'local.acme-deleg.example');
$st = acmeDnsCheck::txtStatus($fq, $val);
check('txtStatus suit le CNAME jusqu\'à la zone cible', $st['state'] === 'visible' && $st['zone'] === 'acme-deleg.example'
    && $st['name'] === 'local.acme-deleg.example', json_encode($st));
check('cnameTarget : pas de CNAME → null', acmeDnsCheck::cnameTarget('_acme-challenge.www.example.org') === null);
simReset();
$sim['down'] = array('192.0.2.14', '192.0.2.15', '2001:db8::14', '2001:db8::15');
$sim['sysCname'][$fq] = 'local.acme-deleg.example.';
check('cnameTarget : repli sur le résolveur du système', acmeDnsCheck::cnameTarget($fq) === 'local.acme-deleg.example');

// Solveur + vraie vérification en DoH : 90 s avant la 1re requête, « pas vu » ⇒ on continue.
simReset();
acmeDnsCheck::$mode = 'doh';
$sim['doh']['cloudflare-dns.com'] = array();
$dns = new testSolverDns(new fakeDnsProvider(array()), array('propagationTimeout' => 120, 'pollInterval' => 30));
$dns->real = true;
$firstDoh = null;
acmeDnsCheck::$dohHook = function ($endpoint, $name) use (&$sim, &$firstDoh, $dns) {
    if ($firstDoh === null) {
        $firstDoh = $dns->clock;
    }
    $sim['dohCalls'][] = $endpoint;
    return array();
};
$logs = array();
$dns->setLogger($logger);
$dns->prepare('jeedom.example.org', 't', 't.k');
$threw = false;
try {
    $dns->waitReady();
} catch (Throwable $e) {
    $threw = true;
}
check('DoH seul, pas vu : pas d\'exception', !$threw);
check('DoH : première requête 90 s après la publication', $firstDoh === 1000 + 90, 'à ' . ((int) $firstDoh - 1000) . ' s');
check('DoH, pas vu : avertissement et délai de sécurité', levelCount($logs, 'warning') >= 1 && $dns->clock - 1000 >= 120 + 60,
    'horloge +' . ($dns->clock - 1000));
acmeDnsCheck::reset();
acmeDnsCheck::$mode = 'auto';

/* ------------------------------------------------------------------ */
section('acmeDnsCheck : DNS réel');

if ($offline) {
    echo "  (ignoré : --offline)\n";
} else {
    $spf = null;
    $records = @dns_get_record('google.com', DNS_TXT);
    foreach (is_array($records) ? $records : array() as $r) {
        $txt = isset($r['txt']) ? $r['txt'] : '';
        if (strpos($txt, 'v=spf1') === 0) {
            $spf = $txt;
        }
    }
    if ($spf === null) {
        echo "  (ignoré : TXT SPF de google.com introuvable par le résolveur local)\n";
    } else {
        $dnsLogs = array();
        $dnsLogger = function ($level, $message) use (&$dnsLogs) {
            $dnsLogs[] = "[$level] $message";
        };
        foreach (array('auto', 'doh') as $mode) {
            acmeDnsCheck::reset();
            acmeDnsCheck::$mode = $mode;
            $t = microtime(true);
            $ok = acmeDnsCheck::txtVisible('google.com', $spf, $dnsLogger);
            check("[$mode] TXT SPF de google.com visible (" . round(microtime(true) - $t, 1) . ' s)', $ok,
                implode(' | ', $dnsLogs));
            $ko = acmeDnsCheck::txtVisible('google.com', 'valeur-absurde-' . bin2hex(random_bytes(6)), $dnsLogger);
            check("[$mode] valeur absurde non visible", !$ko);
            $nx = acmeDnsCheck::txtVisible('_acme-challenge.inexistant-' . bin2hex(random_bytes(4)) . '.google.com', 'x', $dnsLogger);
            check("[$mode] nom inexistant → faux", !$nx);
        }

        // Requête directe à un serveur d'autorité (UDP brut).
        acmeDnsCheck::reset();
        acmeDnsCheck::$mode = 'direct';
        $zone = null;
        $servers = acmeDnsCheck::authoritativeServers('_acme-challenge.google.com', null, $zone);
        check('serveurs d\'autorité de google.com trouvés', count($servers) > 0 && $zone === 'google.com',
            $zone . ' ' . implode(',', $servers));
        if (count($servers) > 0) {
            $r = acmeDnsCheck::queryServer($servers[0], 'google.com');
            if ($r === null) {
                echo "  (UDP/TCP 53 sortant bloqué ? requête directe sans réponse ; le repli DoH couvre ce cas)\n";
            } else {
                check('requête directe : SPF présent', in_array($spf, $r['txt'], true));
                // Sans EDNS (512 octets), le jeu de TXT de google.com est tronqué : TCP doit tout rendre.
                $pkt = acmeDnsCheck::buildQuery(4242, 'google.com', acmeDnsCheck::TYPE_TXT, false);
                $udp = new ReflectionMethod('acmeDnsCheck', 'sendUdp');
                $udp->setAccessible(true);
                $tcp = new ReflectionMethod('acmeDnsCheck', 'sendTcp');
                $tcp->setAccessible(true);
                $rawUdp = $udp->invoke(null, $servers[0], $pkt, 4242);
                $rawTcp = $tcp->invoke(null, $servers[0], $pkt, 4242);
                if ($rawUdp !== null && $rawTcp !== null) {
                    $pu = acmeDnsCheck::parseResponse($rawUdp, 'google.com');
                    $pt = acmeDnsCheck::parseResponse($rawTcp, 'google.com');
                    check('TCP (préfixe de longueur) : réponse complète' . ($pu['tc'] ? ' après TC en UDP' : ''),
                        !$pt['tc'] && in_array($spf, $pt['txt'], true) && count($pt['txt']) >= count($pu['txt']));
                }
            }
        }

        // Port 53 sortant bloqué (simulé : serveur d'autorité injoignable, TEST-NET-1)
        // → repli automatique sur DoH.
        acmeDnsCheck::reset();
        acmeDnsCheck::$mode = 'auto';
        $oldTimeout = acmeDnsCheck::$timeout;
        acmeDnsCheck::$timeout = 1;
        $cache = new ReflectionProperty('acmeDnsCheck', 'nsCache');
        $cache->setAccessible(true);
        $cache->setValue(null, array('google.com' => array('192.0.2.1')));
        $dnsLogs = array();
        $t = microtime(true);
        $ok = acmeDnsCheck::txtVisible('google.com', $spf, $dnsLogger);
        $fellBack = count(array_filter($dnsLogs, function ($l) { return strpos($l, 'DNS-over-HTTPS') !== false; })) > 0;
        check('serveur d\'autorité injoignable → repli DoH (' . round(microtime(true) - $t, 1) . ' s)', $ok && $fellBack,
            implode(' | ', $dnsLogs));
        acmeDnsCheck::$timeout = $oldTimeout;

        // Adresses d'un serveur d'autorité : IPv4 et IPv6.
        $rh = new ReflectionMethod('acmeDnsCheck', 'resolveHost');
        $rh->setAccessible(true);
        $addrs = $rh->invoke(null, 'dns14.ovh.net');
        $has4 = count(array_filter($addrs, function ($a) { return strpos($a, ':') === false; })) > 0;
        $has6 = count(array_filter($addrs, function ($a) { return strpos($a, ':') !== false; })) > 0;
        check('resolveHost(dns14.ovh.net) : IPv4 et IPv6', $has4 && $has6, implode(', ', $addrs));

        // État détaillé réel.
        acmeDnsCheck::reset();
        $st = acmeDnsCheck::txtStatus('google.com', $spf);
        check('txtStatus réel : visible (' . $st['method'] . ')', $st['state'] === 'visible', json_encode($st));

        // CNAME : www.github.com → github.com (même zone, suivi exigé).
        $gh = null;
        $records = @dns_get_record('github.com', DNS_TXT);
        foreach (is_array($records) ? $records : array() as $r) {
            if (isset($r['txt']) && strpos($r['txt'], 'v=spf1') === 0) {
                $gh = $r['txt'];
            }
        }
        if ($gh === null) {
            echo "  (ignoré : TXT SPF de github.com introuvable)\n";
        } else {
            foreach (array('auto', 'doh') as $mode) {
                acmeDnsCheck::reset();
                acmeDnsCheck::$mode = $mode;
                check("[$mode] CNAME suivi (www.github.com → github.com)",
                    acmeDnsCheck::txtVisible('www.github.com', $gh, $dnsLogger), implode(' | ', array_slice($dnsLogs, -5)));
            }
        }
        acmeDnsCheck::$mode = 'auto';
        acmeDnsCheck::reset();
    }
}

echo "\n$passes réussi(s), $failures échec(s)\n";
exit($failures ? 1 : 0);

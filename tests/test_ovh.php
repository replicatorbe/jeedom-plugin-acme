<?php
/* This file is part of the Jeedom acme plugin.
 * Auteur : sMug (Jérôme Fafchamps) — Licence AGPL.
 *
 * Tests du fournisseur DNS OVHcloud (M2), avec un transport HTTP simulé.
 *   php tests/test_ovh.php
 *
 * Test réel facultatif : définir OVH_AK, OVH_AS, OVH_CK (et OVH_ENDPOINT,
 * défaut ovh-eu). Avec OVH_TEST_DOMAIN en plus (ex. jeedom.example.org), un
 * TXT de test est posé, vérifié puis retiré.
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
require_once $root . '/core/class/acmeDns.class.php';
require_once $root . '/core/class/acmeDnsOvh.class.php';

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

/* Faux serveur OVH : routes « MÉTHODE chemin » => réponse ou callable. */
class fakeOvh {
    public $routes = array();
    public $requests = array();
    public $serverTime;
    public function __construct() {
        $this->serverTime = time() + 100;   // horloge OVH en avance de 100 s
    }
    public function __invoke(string $method, string $url, array $headers, string $body): array {
        $path = substr($url, strlen('https://eu.api.ovh.com/1.0'));
        $h = array();
        foreach ($headers as $line) {
            list($k, $v) = explode(':', $line, 2);
            $h[strtolower(trim($k))] = trim($v);
        }
        $this->requests[] = array('method' => $method, 'url' => $url, 'path' => $path, 'headers' => $h, 'body' => $body);
        if ($method === 'GET' && $path === '/auth/time') {
            return array('code' => 200, 'body' => (string) $this->serverTime);
        }
        $key = $method . ' ' . $path;
        if (!isset($this->routes[$key])) {
            return array('code' => 404, 'body' => json_encode(array('message' => 'This service does not exist')));
        }
        $r = $this->routes[$key];
        return is_callable($r) ? $r($body) : $r;
    }
    public function calls(): array {
        $out = array();
        foreach ($this->requests as $r) {
            $out[] = $r['method'] . ' ' . $r['path'];
        }
        return $out;
    }
}

function ok($data): array {
    return array('code' => 200, 'body' => json_encode($data));
}

function ovhError(int $code, string $message, string $errorCode = ''): array {
    $d = array('message' => $message);
    if ($errorCode !== '') {
        $d['errorCode'] = $errorCode;
    }
    return array('code' => $code, 'body' => json_encode($d));
}

$AS = 'secretAS';
$CK = 'consumerCK';
$AK = 'appKeyAK1234';
$config = array('endpoint' => 'ovh-eu', 'application_key' => $AK, 'application_secret' => $AS, 'consumer_key' => $CK);

$logs = array();
$logger = function (string $level, string $message) use (&$logs) {
    $logs[] = "[$level] $message";
};

/* ------------------------------------------------------------------ */
section('Signature et points d\'accès');

// Vecteurs calculés à la main :
//   printf '%s' 'secretAS+consumerCK+GET+https://eu.api.ovh.com/1.0/domain/zone++1700000000' | sha1sum
check('signature GET (corps vide)',
    acmeDnsOvh::signature($AS, $CK, 'GET', 'https://eu.api.ovh.com/1.0/domain/zone', '', 1700000000)
    === '$1$06bd2ea4d16316dfcfffbdf67b3f0ecc625cccbd');
$body = '{"fieldType":"TXT","subDomain":"_acme-challenge.jeedom","target":"abc","ttl":60}';
check('signature POST (corps JSON)',
    acmeDnsOvh::signature($AS, $CK, 'POST', 'https://eu.api.ovh.com/1.0/domain/zone/example.org/record', $body, 1700000000)
    === '$1$d6e092d4837bf7dcc8af7a748151cf7309b2fd77');

check('createTokenUrl ovh-eu', acmeDnsOvh::createTokenUrl('ovh-eu')
    === 'https://eu.api.ovh.com/createToken/?GET=/domain/zone&GET=/domain/zone/*&POST=/domain/zone/*&DELETE=/domain/zone/*',
    acmeDnsOvh::createTokenUrl('ovh-eu'));
check('createTokenUrl ovh-ca', strpos(acmeDnsOvh::createTokenUrl('ovh-ca'), 'https://ca.api.ovh.com/createToken/?') === 0);
check('createTokenUrl ovh-us', strpos(acmeDnsOvh::createTokenUrl('ovh-us'), 'https://api.us.ovhcloud.com/createToken/?') === 0);
check('createTokenUrl kimsufi-eu', strpos(acmeDnsOvh::createTokenUrl('kimsufi-eu'), 'https://eu.api.kimsufi.com/createToken/?') === 0);
check('7 points d\'accès', count(acmeDnsOvh::ENDPOINTS) == 7);
$refused = false;
try {
    acmeDnsOvh::endpointUrl('ovh-mars');
} catch (acmeException $e) {
    $refused = true;
}
check('point d\'accès inconnu refusé', $refused);

$fields = acmeDnsOvh::getFields();
check('getFields : 4 champs attendus', array_keys($fields) === array('endpoint', 'application_key', 'application_secret', 'consumer_key'));
check('getFields : secrets en password', $fields['application_secret']['type'] === 'password' && $fields['consumer_key']['type'] === 'password');
check('getFields : endpoint select, défaut ovh-eu', $fields['endpoint']['type'] === 'select' && $fields['endpoint']['default'] === 'ovh-eu'
    && isset($fields['endpoint']['options']['ovh-eu']));
check('getFields : aide AK alignée sur le bouton « Créer un jeton OVH »',
    strpos($fields['application_key']['help'], '« Créer un jeton OVH »') !== false);
check('getFields : aide de validité', strpos($fields['consumer_key']['help'],
    "Validité : Illimitée (sinon les renouvellements automatiques échoueront à l'expiration du jeton)") !== false);
check('getLabel', acmeDnsOvh::getLabel() === 'OVHcloud');
$probe = new acmeDnsOvh($config);
check('méthodes facultatives présentes (listTxt, expectedNameServers)',
    method_exists($probe, 'listTxt') && method_exists($probe, 'expectedNameServers'));
check('expectedNameServers : ovh.net, ovh.ca, anycast.me', count(array_intersect(array('ovh.net', 'ovh.ca', 'anycast.me'),
    $probe->expectedNameServers())) == 3);
check('registre acmeDns', acmeDns::providers() === array('ovh' => 'acmeDnsOvh')
    && acmeDns::create('ovh', $config) instanceof acmeDnsOvh);

/* ------------------------------------------------------------------ */
section('Détection de zone');

$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org', 'example.org', 'champs.be', 'other.example.org'));
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$loc = $ovh->locate('_acme-challenge.jeedom.example.org');
check('jeedom.example.org → zone example.org', $loc['zone'] === 'example.org', json_encode($loc));
check('subDomain _acme-challenge.jeedom', $loc['sub'] === '_acme-challenge.jeedom');
$loc = $ovh->locate('_acme-challenge.x.other.example.org.');
check('plus long suffixe (other.example.org)', $loc['zone'] === 'other.example.org' && $loc['sub'] === '_acme-challenge.x');
$loc = $ovh->locate('_acme-challenge.example.org');
check('apex : subDomain _acme-challenge', $loc['zone'] === 'example.org' && $loc['sub'] === '_acme-challenge');
$refused = false;
try {
    $ovh->locate('_acme-challenge.inconnu.net');
} catch (acmeException $e) {
    $refused = true;
}
check('zone absente → acmeException', $refused);
check('liste des zones lue une seule fois', count(array_keys($srv->calls(), 'GET /domain/zone')) == 1);

// Liste non autorisée : sondage des suffixes.
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ovhError(403, 'This call has not been granted', 'NOT_GRANTED_CALL');
$srv->routes['GET /domain/zone/example.org'] = ok(array('name' => 'example.org'));
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$loc = $ovh->locate('_acme-challenge.jeedom.example.org');
check('sans droit de liste : zone trouvée par sondage', $loc['zone'] === 'example.org' && $loc['sub'] === '_acme-challenge.jeedom',
    implode(', ', $srv->calls()));

/* ------------------------------------------------------------------ */
section('Séquence addTxt / commit / removeTxt');

$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$nextId = 1000;
$srv->routes['POST /domain/zone/example.org/record'] = function ($body) use (&$nextId) {
    $d = json_decode($body, true);
    $d['id'] = ++$nextId;
    $d['zone'] = 'example.org';
    return ok($d);
};
$srv->routes['POST /domain/zone/example.org/refresh'] = array('code' => 200, 'body' => 'null');
$srv->routes['DELETE /domain/zone/example.org/record/1001'] = array('code' => 200, 'body' => 'null');
$srv->routes['DELETE /domain/zone/example.org/record/1002'] = ovhError(404, 'The requested object (id = 1002) does not exist');

$logs = array();
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$ovh->addTxt('_acme-challenge.jeedom.example.org', 'valeurA');
$ovh->addTxt('_acme-challenge.jeedom.example.org', 'valeurB');
$ovh->commit();
$ovh->commit();   // rien de neuf : pas de second refresh
$ovh->removeTxt('_acme-challenge.jeedom.example.org', 'valeurA');
$ovh->removeTxt('_acme-challenge.jeedom.example.org', 'valeurB');   // 404 toléré
$ovh->commit();

$expected = array(
    'GET /auth/time',
    'GET /domain/zone',
    'POST /domain/zone/example.org/record',
    'POST /domain/zone/example.org/record',
    'POST /domain/zone/example.org/refresh',
    'DELETE /domain/zone/example.org/record/1001',
    'DELETE /domain/zone/example.org/record/1002',
    'POST /domain/zone/example.org/refresh',
);
check('séquence d\'appels', $srv->calls() === $expected, implode(', ', $srv->calls()));

$post = $srv->requests[2];
check('corps POST record', json_decode($post['body'], true) === array(
    'fieldType' => 'TXT', 'subDomain' => '_acme-challenge.jeedom', 'target' => 'valeurA', 'ttl' => 60), $post['body']);
check('/auth/time non signé', !isset($srv->requests[0]['headers']['x-ovh-signature']));
$h = $post['headers'];
check('en-têtes X-Ovh-*', isset($h['x-ovh-application'], $h['x-ovh-consumer'], $h['x-ovh-timestamp'], $h['x-ovh-signature'])
    && $h['x-ovh-application'] === $AK && $h['x-ovh-consumer'] === $CK);
check('horodatage corrigé du décalage (+100 s)', abs((int) $h['x-ovh-timestamp'] - (time() + 100)) <= 2, $h['x-ovh-timestamp']);
check('signature de la requête vérifiable', $h['x-ovh-signature']
    === acmeDnsOvh::signature($AS, $CK, 'POST', $post['url'], $post['body'], (int) $h['x-ovh-timestamp']));
$joined = implode("\n", $logs);
check('aucun secret dans les journaux', strpos($joined, $AS) === false && strpos($joined, $CK) === false, $joined);

// removeTxt sans identifiant retenu (autre processus) : recherche puis comparaison de la cible.
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$srv->routes['GET /domain/zone/example.org/record?fieldType=TXT&subDomain=_acme-challenge.jeedom'] = ok(array(11, 12));
$srv->routes['GET /domain/zone/example.org/record/11'] = ok(array('id' => 11, 'target' => '"valeurA"'));
$srv->routes['GET /domain/zone/example.org/record/12'] = ok(array('id' => 12, 'target' => 'autre'));
$srv->routes['DELETE /domain/zone/example.org/record/11'] = array('code' => 200, 'body' => 'null');
$srv->routes['POST /domain/zone/example.org/refresh'] = array('code' => 200, 'body' => 'null');
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$ovh->removeTxt('_acme-challenge.jeedom.example.org', 'valeurA');
$ovh->commit();
$calls = $srv->calls();
check('recherche par fieldType/subDomain, cible entre guillemets reconnue',
    in_array('DELETE /domain/zone/example.org/record/11', $calls, true)
    && !in_array('DELETE /domain/zone/example.org/record/12', $calls, true)
    && end($calls) === 'POST /domain/zone/example.org/refresh', implode(', ', $calls));

// listTxt : valeurs sans guillemets ; removeTxt réutilise la liste (pas de nouvelle lecture).
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$srv->routes['GET /domain/zone/example.org/record?fieldType=TXT&subDomain=_acme-challenge.jeedom'] = ok(array(21, 22));
$srv->routes['GET /domain/zone/example.org/record/21'] = ok(array('id' => 21, 'target' => '"' . str_repeat('a', 43) . '"'));
$srv->routes['GET /domain/zone/example.org/record/22'] = ok(array('id' => 22, 'target' => 'autre'));
$srv->routes['DELETE /domain/zone/example.org/record/21'] = array('code' => 200, 'body' => 'null');
$srv->routes['POST /domain/zone/example.org/refresh'] = array('code' => 200, 'body' => 'null');
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$values = $ovh->listTxt('_acme-challenge.jeedom.example.org');
check('listTxt : valeurs sans guillemets', $values === array(str_repeat('a', 43), 'autre'), json_encode($values));
$before = count($srv->requests);
$ovh->removeTxt('_acme-challenge.jeedom.example.org', str_repeat('a', 43));
$after = array_slice($srv->calls(), $before);
check('removeTxt après listTxt : suppression directe, sans relecture', $after === array('DELETE /domain/zone/example.org/record/21'),
    implode(', ', $after));
$ovh->commit();
check('removeTxt après listTxt : zone republiée', end($srv->requests)['path'] === '/domain/zone/example.org/refresh');

// recordId : identifiant retenu à la création (pour le fichier d'état du solveur).
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$srv->routes['POST /domain/zone/example.org/record'] = ok(array('id' => 4242));
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
check('méthodes facultatives recordId et removeTxtById présentes', method_exists($ovh, 'recordId') && method_exists($ovh, 'removeTxtById'));
check('recordId avant addTxt : null', $ovh->recordId('_acme-challenge.jeedom.example.org', 'valeurA') === null);
$ovh->addTxt('_acme-challenge.jeedom.example.org', 'valeurA');
check('recordId après addTxt : id OVH', $ovh->recordId('_acme-challenge.jeedom.example.org.', 'valeurA') === '4242');
check('recordId d\'une autre valeur : null', $ovh->recordId('_acme-challenge.jeedom.example.org', 'valeurB') === null);

// removeTxtById : vérifie l'enregistrement (nom, valeur) puis le supprime, sans recherche.
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$srv->routes['GET /domain/zone/example.org/record/31'] = ok(array('id' => 31, 'fieldType' => 'TXT',
    'subDomain' => '_acme-challenge.jeedom', 'target' => '"valeurA"'));
$srv->routes['DELETE /domain/zone/example.org/record/31'] = array('code' => 200, 'body' => 'null');
$srv->routes['POST /domain/zone/example.org/refresh'] = array('code' => 200, 'body' => 'null');
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$removed = $ovh->removeTxtById('_acme-challenge.jeedom.example.org', 'valeurA', '31');
$ovh->commit();
check('removeTxtById : true', $removed === true);
check('removeTxtById : GET puis DELETE par id, sans recherche, puis refresh', $srv->calls() === array(
    'GET /auth/time', 'GET /domain/zone', 'GET /domain/zone/example.org/record/31',
    'DELETE /domain/zone/example.org/record/31', 'POST /domain/zone/example.org/refresh'), implode(', ', $srv->calls()));

// removeTxtById : enregistrement déjà supprimé (404) → false, sans erreur ni refresh.
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$removed = null;
$threw = false;
try {
    $removed = $ovh->removeTxtById('_acme-challenge.jeedom.example.org', 'valeurA', '32');
    $ovh->commit();
} catch (acmeException $e) {
    $threw = true;
}
check('removeTxtById : id inconnu → false sans erreur', !$threw && $removed === false);
check('removeTxtById : id inconnu → ni DELETE ni refresh', count(array_filter($srv->calls(), function ($c) {
    return strpos($c, 'DELETE') === 0 || strpos($c, '/refresh') !== false; })) == 0, implode(', ', $srv->calls()));

// removeTxtById : l'id désigne un autre TXT (valeur d'un autre outil) → jamais supprimé ;
// recherche par nom et valeur exacte à la place.
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$srv->routes['GET /domain/zone/example.org/record/33'] = ok(array('id' => 33, 'fieldType' => 'TXT',
    'subDomain' => '_acme-challenge.jeedom', 'target' => str_repeat('c', 43)));
$srv->routes['GET /domain/zone/example.org/record?fieldType=TXT&subDomain=_acme-challenge.jeedom'] = ok(array(33, 34));
$srv->routes['GET /domain/zone/example.org/record/34'] = ok(array('id' => 34, 'target' => '"valeurA"'));
$srv->routes['DELETE /domain/zone/example.org/record/34'] = array('code' => 200, 'body' => 'null');
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$removed = $ovh->removeTxtById('_acme-challenge.jeedom.example.org', 'valeurA', '33');
$calls = $srv->calls();
check('removeTxtById : id réattribué → TXT étranger conservé', !in_array('DELETE /domain/zone/example.org/record/33', $calls, true),
    implode(', ', $calls));
check('removeTxtById : id réattribué → retrait par valeur exacte', $removed === true
    && in_array('DELETE /domain/zone/example.org/record/34', $calls, true), implode(', ', $calls));

// removeTxt ne supprime que la valeur exacte : un TXT de forme ACME d'un autre outil reste.
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$srv->routes['GET /domain/zone/example.org/record?fieldType=TXT&subDomain=_acme-challenge.jeedom'] = ok(array(41, 42));
$srv->routes['GET /domain/zone/example.org/record/41'] = ok(array('id' => 41, 'target' => str_repeat('d', 43)));
$srv->routes['GET /domain/zone/example.org/record/42'] = ok(array('id' => 42, 'target' => str_repeat('e', 43)));
$srv->routes['DELETE /domain/zone/example.org/record/42'] = array('code' => 200, 'body' => 'null');
$ovh = new acmeDnsOvh($config, $logger);
$ovh->setTransport($srv);
$ovh->removeTxt('_acme-challenge.jeedom.example.org', str_repeat('e', 43));
check('removeTxt : TXT ACME d\'un autre outil conservé', !in_array('DELETE /domain/zone/example.org/record/41', $srv->calls(), true)
    && in_array('DELETE /domain/zone/example.org/record/42', $srv->calls(), true), implode(', ', $srv->calls()));

// Cible d'un CNAME de délégation dans une zone absente du compte : erreur claire.
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ok(array('example.org'));
$ovh = new acmeDnsOvh($config);
$ovh->setTransport($srv);
$msg = '';
try {
    $ovh->addTxt('local.acme-deleg.example', 'v');
} catch (acmeException $e) {
    $msg = $e->getMessage();
}
check('zone de la cible absente → erreur claire', strpos($msg, 'Aucune zone DNS OVH ne correspond à local.acme-deleg.example') !== false, $msg);

/* ------------------------------------------------------------------ */
section('Erreurs');

function expectError(array $routes, callable $action, string $needle, string $label): void {
    $srv = new fakeOvh();
    $srv->routes = $routes;
    $ovh = new acmeDnsOvh($GLOBALS['config']);
    $ovh->setTransport($srv);
    $msg = null;
    try {
        $action($ovh);
    } catch (acmeException $e) {
        $msg = $e->getMessage();
    }
    check($label, $msg !== null && stripos($msg, $needle) !== false, (string) $msg);
}

expectError(array('GET /domain/zone' => ovhError(400, 'Invalid signature', 'INVALID_SIGNATURE')),
    function ($o) { $o->addTxt('_acme-challenge.jeedom.example.org', 'v'); },
    'application secret', 'Invalid signature → conseil sur l\'application secret');
expectError(array('GET /domain/zone' => ok(array('example.org')),
        'POST /domain/zone/example.org/record' => ovhError(403, 'This call has not been granted', 'NOT_GRANTED_CALL')),
    function ($o) { $o->addTxt('_acme-challenge.jeedom.example.org', 'v'); },
    '/domain/zone/*', 'not granted → conseil sur les droits du jeton');
expectError(array('GET /domain/zone' => ovhError(403, 'Invalid credential', 'INVALID_CREDENTIAL')),
    function ($o) { $o->addTxt('_acme-challenge.jeedom.example.org', 'v'); },
    'recréez un jeton', 'Invalid credential → conseil de recréer le jeton');
expectError(array('GET /domain/zone' => ovhError(403, 'Invalid application key', 'INVALID_KEY')),
    function ($o) { $o->addTxt('_acme-challenge.jeedom.example.org', 'v'); },
    "point d'accès", 'Invalid application key → conseil sur le point d\'accès');

$ovh = new acmeDnsOvh($config);
$ovh->setTransport(function () { return array('code' => 0, 'body' => '', 'error' => 'Could not resolve host'); });
$msg = '';
try {
    $ovh->commit();
    $ovh->addTxt('_acme-challenge.jeedom.example.org', 'v');
} catch (acmeException $e) {
    $msg = $e->getMessage();
}
check('réseau injoignable → message clair', strpos($msg, "Impossible de joindre l'API OVH") !== false, $msg);

$ovh = new acmeDnsOvh(array('endpoint' => 'ovh-eu', 'application_key' => 'x'));
$msg = '';
try {
    $ovh->test();
} catch (acmeException $e) {
    $msg = $e->getMessage();
}
check('identifiants incomplets → message clair', strpos($msg, 'application secret') !== false && strpos($msg, 'consumer key') !== false, $msg);

$e = null;
$srv = new fakeOvh();
$srv->routes['GET /domain/zone'] = ovhError(403, 'Invalid credential', 'INVALID_CREDENTIAL');
$ovh = new acmeDnsOvh($config);
$ovh->setTransport($srv);
try {
    $ovh->locate('a.example.org');
} catch (acmeException $ex) {
    $e = $ex;
}
check('code HTTP porté par l\'exception', $e !== null && $e->getCode() == 403);

/* ------------------------------------------------------------------ */
section('test()');

$srv = new fakeOvh();
$srv->routes['GET /auth/currentCredential'] = ok(array('status' => 'validated', 'expiration' => null,
    'rules' => array(array('method' => 'GET', 'path' => '/domain/zone/*'), array('method' => 'POST', 'path' => '/domain/zone/*'))));
$srv->routes['GET /domain/zone'] = ok(array('example.org', 'example.org'));
$ovh = new acmeDnsOvh($config);
$ovh->setTransport($srv);
$summary = $ovh->test();
check('résumé : jeton, droits et zones', strpos($summary, 'sans expiration') !== false
    && strpos($summary, 'POST /domain/zone/*') !== false && strpos($summary, 'example.org, example.org') !== false, $summary);
check('résumé : clé masquée', strpos($summary, 'appK…') !== false && strpos($summary, $AK) === false);

$srv = new fakeOvh();
$srv->routes['GET /auth/currentCredential'] = ok(array('status' => 'pendingValidation'));
$ovh = new acmeDnsOvh($config);
$ovh->setTransport($srv);
$msg = '';
try {
    $ovh->test();
} catch (acmeException $e) {
    $msg = $e->getMessage();
}
check('jeton non validé → acmeException', strpos($msg, 'pendingValidation') !== false, $msg);

$srv = new fakeOvh();
$srv->routes['GET /auth/currentCredential'] = ok(array('status' => 'validated', 'expiration' => '2027-01-01T00:00:00+01:00', 'rules' => array()));
$srv->routes['GET /domain/zone'] = ok(array());
$ovh = new acmeDnsOvh($config);
$ovh->setTransport($srv);
$msg = '';
try {
    $ovh->test();
} catch (acmeException $e) {
    $msg = $e->getMessage();
}
check('aucune zone → acmeException', strpos($msg, 'Aucune zone') !== false, $msg);

/* ------------------------------------------------------------------ */
section('API OVH réelle (facultatif)');

$ak = getenv('OVH_AK');
$as = getenv('OVH_AS');
$ck = getenv('OVH_CK');
if (!$ak || !$as || !$ck) {
    echo "  (ignoré : définir OVH_AK, OVH_AS et OVH_CK pour tester l'API réelle)\n";
} else {
    $realLogs = array();
    $real = new acmeDnsOvh(array(
        'endpoint' => getenv('OVH_ENDPOINT') ?: 'ovh-eu',
        'application_key' => $ak, 'application_secret' => $as, 'consumer_key' => $ck,
    ), function ($level, $message) use (&$realLogs) {
        $realLogs[] = "[$level] $message";
    });
    try {
        $summary = $real->test();
        check('test() réel', true);
        echo preg_replace('/^/m', '        ', $summary) . "\n";
    } catch (acmeException $e) {
        check('test() réel', false, $e->getMessage());
    }
    $domain = getenv('OVH_TEST_DOMAIN');
    if ($domain) {
        $fqdn = '_acme-challenge.' . $domain;
        $value = 'jeedom-acme-test-' . bin2hex(random_bytes(6));
        try {
            $real->addTxt($fqdn, $value);
            $real->commit();
            $seen = false;
            for ($i = 0; $i < 18 && !$seen; $i++) {
                $seen = acmeDnsCheck::txtVisible($fqdn, $value);
                if (!$seen) {
                    sleep(10);
                }
            }
            check('TXT réel visible sur les serveurs d\'autorité', $seen);
        } catch (acmeException $e) {
            check('TXT réel posé', false, $e->getMessage());
        }
        try {
            $real->removeTxt($fqdn, $value);
            $real->commit();
            check('TXT réel retiré', true);
        } catch (acmeException $e) {
            check('TXT réel retiré', false, $e->getMessage());
        }
    } else {
        echo "  (pose d'un TXT réel ignorée : définir OVH_TEST_DOMAIN, ex. jeedom.example.org)\n";
    }
    $joined = implode("\n", $realLogs);
    check('aucun secret dans les journaux (réel)', strpos($joined, $as) === false && strpos($joined, $ck) === false);
}

echo "\n$passes réussi(s), $failures échec(s)\n";
exit($failures ? 1 : 0);

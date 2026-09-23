<?php
/* This file is part of the Jeedom acme plugin.
 * Copyright (C) sMug (Jérôme Fafchamps) — AGPL-3.0-or-later
 *
 * Test RÉEL de acmeClient contre Let's Encrypt STAGING (jamais la production).
 * Aucun certificat n'est émis : le faux solveur interrompt l'émission au
 * premier défi, puis l'autorisation créée est désactivée.
 *
 * Usage : php tests/test_staging.php [domaine] [-v]
 *   domaine : un nom réel sous un domaine public (le vôtre de préférence), à
 *             défaut la variable d'environnement ACME_TEST_DOMAIN. Aucun défaut :
 *             Let's Encrypt refuse les domaines réservés (example.org…), et le
 *             test crée de vraies commandes, jamais validées, sur le staging.
 *   -v      : affiche aussi le journal debug du client
 * Code retour 0 si tout passe, 1 sinon.
 */

require_once __DIR__ . '/../core/class/acmeClient.class.php';

/* Le vrai acmeSolver (module M2) n'est pas chargé : ce test ne dépend que de M1.
 * Définition minimale conforme au contrat (CONCEPTION.md §4.3) si besoin. */
if (!class_exists('acmeSolver')) {
    abstract class acmeSolver {
        protected $logger = null;
        public function setLogger(?callable $logger): void {
            $this->logger = $logger;
        }
        abstract public function getType(): string;
        abstract public function prepare(string $domain, string $token, string $keyAuthorization): void;
        public function waitReady(): void {
        }
        abstract public function cleanup(): void;
    }
}

/* Faux solveur : note ce qu'il reçoit et interrompt l'émission dans prepare(). */
class acmeTestInterruptSolver extends acmeSolver {
    public $type;
    public $prepared = array();
    public $cleanupCalls = 0;
    public $waitReadyCalls = 0;
    public function __construct(string $type) {
        $this->type = $type;
    }
    public function getType(): string {
        return $this->type;
    }
    public function prepare(string $domain, string $token, string $keyAuthorization): void {
        $this->prepared[] = array('domain' => $domain, 'token' => $token, 'keyAuthorization' => $keyAuthorization);
        throw new RuntimeException('interruption volontaire du test');
    }
    public function waitReady(): void {
        $this->waitReadyCalls++;
    }
    public function cleanup(): void {
        $this->cleanupCalls++;
    }
}

$failures = 0;
$count = 0;
function check(string $label, bool $ok, string $detail = ''): void {
    global $failures, $count;
    $count++;
    if (!$ok) {
        $failures++;
    }
    echo ($ok ? '  OK     ' : '  ÉCHEC  ') . $label . ($detail !== '' ? ' — ' . $detail : '') . "\n";
}
function section(string $title): void {
    echo "\n== " . $title . " ==\n";
}

$args = array_slice($argv, 1);
$verbose = in_array('-v', $args, true);
$args = array_values(array_diff($args, array('-v')));
$domain = isset($args[0]) ? $args[0] : (string) getenv('ACME_TEST_DOMAIN');
if ($domain === '') {
    fwrite(STDERR, "Usage : php tests/test_staging.php <domaine> [-v]   (ou ACME_TEST_DOMAIN=<domaine>)\n"
        . "Donnez un nom réel sous un domaine public, le vôtre de préférence : Let's Encrypt refuse\n"
        . "les domaines réservés (example.org…). Rien n'est émis ni validé, tout reste sur le staging.\n");
    exit(2);
}

$journal = array();
$logger = function (string $level, string $message) use (&$journal, $verbose) {
    $journal[] = array($level, $message);
    if ($verbose || $level !== 'debug') {
        echo '         [' . $level . '] ' . $message . "\n";
    }
};

$accountKey = acmeCrypto::generateKey('ec256');   // clé jetable, jamais conservée
$authzToDeactivate = array();
$client = null;

try {
    section('Let\'s Encrypt STAGING : annuaire et compte');
    $client = new acmeClient(acmeClient::LETSENCRYPT_STAGING, $accountKey, $logger);
    $dir = $client->getDirectory();
    check('annuaire lu', isset($dir['newOrder'], $dir['newNonce'], $dir['newAccount']));
    check('requiresEab() = false', $client->requiresEab() === false);

    // Sans compte, issue() doit refuser proprement.
    $thrown = null;
    try {
        $client->issue(array($domain), acmeCrypto::generateKey('ec256'), new acmeTestInterruptSolver('dns-01'));
    } catch (acmeException $e) {
        $thrown = $e;
    }
    check('issue() sans compte : acmeException', $thrown !== null, $thrown ? $thrown->getMessage() : '');

    $kid = $client->registerAccount('');
    check('compte créé, URL renvoyée', (bool) preg_match('#^https://acme-staging-v02\.api\.letsencrypt\.org/#', $kid), $kid);
    $kid2 = $client->registerAccount('');
    check('même clé = même compte', $kid2 === $kid);

    // Un second client avec setAccountUrl() doit fonctionner sans newAccount.
    $client2 = new acmeClient(acmeClient::LETSENCRYPT_STAGING, $accountKey, $logger);
    $client2->setAccountUrl($kid);
    $acct = $client2->fetch($kid);
    check('setAccountUrl() + POST-as-GET du compte', isset($acct['status']) && $acct['status'] === 'valid', isset($acct['status']) ? $acct['status'] : '?');

    // Un nonce déjà consommé doit être rattrapé par le réessai badNonce.
    $prop = new ReflectionProperty('acmeClient', 'nonce');
    $prop->setAccessible(true);   // sans effet en 8.1+, nécessaire en 7.4
    $used = $prop->getValue($client2);
    $client2->fetch($kid);        // consomme ce nonce
    $prop->setValue($client2, $used);
    $acct = $client2->fetch($kid);
    check('badNonce : nouvel essai transparent', isset($acct['status']) && $acct['status'] === 'valid');
    $badNonceLogged = false;
    foreach ($journal as $line) {
        if (strpos($line[1], 'Nonce refusé') !== false) {
            $badNonceLogged = true;
        }
    }
    check('badNonce : réessai journalisé', $badNonceLogged);

    section('Compte : contact, erreurs de compte, réseau');
    $client2->updateContact('acme-test@' . $domain);
    check('updateContact(e-mail) accepté', true);
    $client2->updateContact('');
    check('updateContact(\'\') accepté', true);

    // Clé du compte A présentée avec le kid d'un compte B.
    $keyB = acmeCrypto::generateKey('ec256');
    $clientB = new acmeClient(acmeClient::LETSENCRYPT_STAGING, $keyB, $logger);
    $kidB = $clientB->registerAccount('');
    $wrong = new acmeClient(acmeClient::LETSENCRYPT_STAGING, $accountKey, $logger);
    $wrong->setAccountUrl($kidB);
    $thrown = null;
    try {
        $wrong->fetch($kidB);
    } catch (Throwable $e) {
        $thrown = $e;
    }
    check('kid d\'un autre compte : isAccountProblem() = missing',
        $thrown !== null && acmeClient::isAccountProblem($thrown) === 'missing', $thrown ? $thrown->getMessage() : 'aucune exception');

    // kid inexistant.
    $ghost = new acmeClient(acmeClient::LETSENCRYPT_STAGING, $accountKey, $logger);
    $ghost->setAccountUrl(preg_replace('#\d+$#', '999999999999', $kid));
    $thrown = null;
    try {
        $ghost->fetch($kid);
    } catch (Throwable $e) {
        $thrown = $e;
    }
    check('kid inexistant : isAccountProblem() = missing',
        $thrown !== null && acmeClient::isAccountProblem($thrown) === 'missing', $thrown ? $thrown->getMessage() : 'aucune exception');

    // Compte désactivé : requête signée par kid, puis newAccount avec la même clé.
    $clientB->deactivateAccount();
    check('deactivateAccount()', true);
    $thrown = null;
    try {
        $clientB->newOrder(array($domain));
    } catch (Throwable $e) {
        $thrown = $e;
    }
    check('compte désactivé (kid) : isAccountProblem() = deactivated',
        $thrown !== null && acmeClient::isAccountProblem($thrown) === 'deactivated', $thrown ? $thrown->getMessage() : 'aucune exception');
    $thrown = null;
    try {
        (new acmeClient(acmeClient::LETSENCRYPT_STAGING, $keyB, $logger))->registerAccount('');
    } catch (Throwable $e) {
        $thrown = $e;
    }
    check('compte désactivé (newAccount) : isAccountProblem() = deactivated',
        $thrown !== null && acmeClient::isAccountProblem($thrown) === 'deactivated', $thrown ? $thrown->getMessage() : 'aucune exception');
    check('erreur ordinaire : isAccountProblem() = \'\'',
        acmeClient::isAccountProblem(new acmeException('x', array('type' => 'urn:ietf:params:acme:error:rejectedIdentifier', 'detail' => 'deactivated'))) === ''
        && acmeClient::isAccountProblem(new RuntimeException('JWS verification error')) === '');

    // Erreur de transport : un POST-as-GET est rejoué (2, 4, 8 s, nonce neuf),
    // une requête non idempotente ne l'est pas.
    $dead = 'https://127.0.0.1:1/acme/authz/test';
    $before = count($journal);
    $t0 = time();
    $thrown = null;
    try {
        $client2->fetch($dead);
    } catch (Throwable $e) {
        $thrown = $e;
    }
    $retries = 0;
    foreach (array_slice($journal, $before) as $line) {
        if (strpos($line[1], 'nouvel essai') !== false && strpos($line[1], '127.0.0.1') !== false) {
            $retries++;
        }
    }
    check('réseau, POST-as-GET : ' . acmeClient::NETWORK_RETRIES . ' nouveaux essais puis erreur réseau',
        $thrown instanceof acmeException && $thrown->getCode() === acmeClient::NETWORK_ERROR && $retries === acmeClient::NETWORK_RETRIES,
        $retries . ' essais en ' . (time() - $t0) . ' s' . ($thrown ? ', ' . $thrown->getMessage() : ''));
    check('réseau, erreur réseau : isAccountProblem() = \'\'', $thrown !== null && acmeClient::isAccountProblem($thrown) === '');
    $before = count($journal);
    $thrown = null;
    try {
        $client2->deactivateAuthorization($dead);
    } catch (Throwable $e) {
        $thrown = $e;
    }
    $retries = 0;
    foreach (array_slice($journal, $before) as $line) {
        if (strpos($line[1], 'nouvel essai') !== false) {
            $retries++;
        }
    }
    check('réseau, requête non idempotente : aucun nouvel essai',
        $thrown instanceof acmeException && $thrown->getCode() === acmeClient::NETWORK_ERROR && $retries === 0, (string) $retries);

    section('Émission interrompue au défi (' . $domain . ')');
    foreach (array('dns-01', 'http-01') as $type) {
        $solver = new acmeTestInterruptSolver($type);
        $thrown = null;
        try {
            $client->issue(array($domain), acmeCrypto::generateKey('ec256'), $solver);
        } catch (Throwable $e) {
            $thrown = $e;
        }
        check($type . ' : issue() interrompue par une acmeException', $thrown instanceof acmeException,
            $thrown ? get_class($thrown) . ' : ' . $thrown->getMessage() : 'aucune exception');
        check($type . ' : prepare() appelé une fois', count($solver->prepared) === 1);
        check($type . ' : cleanup() appelé malgré l\'exception', $solver->cleanupCalls === 1, (string) $solver->cleanupCalls);
        check($type . ' : waitReady() non appelé', $solver->waitReadyCalls === 0);
        if (count($solver->prepared) === 1) {
            $p = $solver->prepared[0];
            check($type . ' : domaine transmis', $p['domain'] === $domain, $p['domain']);
            check($type . ' : keyAuthorization = token.empreinte',
                $p['keyAuthorization'] === $p['token'] . '.' . acmeCrypto::thumbprint($accountKey));
        }
    }

    section('Autorisations et défis proposés');
    $order = $client->newOrder(array($domain));
    check('commande pending', isset($order['status']) && in_array($order['status'], array('pending', 'ready'), true),
        isset($order['status']) ? $order['status'] : '?');
    check('une autorisation', count($order['authorizations']) === 1);
    foreach ($order['authorizations'] as $authzUrl) {
        $authz = $client->fetch($authzUrl);
        $types = array();
        foreach ($authz['challenges'] as $c) {
            $types[] = $c['type'];
        }
        check('identifiant = ' . $domain, $authz['identifier']['value'] === $domain);
        check('défi http-01 proposé', in_array('http-01', $types, true), implode(', ', $types));
        check('défi dns-01 proposé', in_array('dns-01', $types, true));
        if ($authz['status'] === 'pending') {
            $authzToDeactivate[] = $authzUrl;
        }
    }
} catch (Throwable $e) {
    check('exception inattendue', false, get_class($e) . ' : ' . $e->getMessage()
        . ($e instanceof acmeException && count($e->getProblem()) ? ' ' . json_encode($e->getProblem()) : ''));
}

// Ménage : désactivation des autorisations restées en attente, y compris
// celles des émissions interrompues (URL relevées dans le journal debug).
foreach ($journal as $line) {
    if (preg_match('#(https://acme-staging\S+/acme/authz/\S+)#', $line[1], $m) && !in_array($m[1], $authzToDeactivate, true)) {
        $authzToDeactivate[] = $m[1];
    }
}
if ($client !== null && count($authzToDeactivate)) {
    section('Ménage');
    $done = 0;
    $errors = array();
    foreach ($authzToDeactivate as $url) {
        try {
            $authz = $client->fetch($url);
            if (isset($authz['status']) && $authz['status'] === 'pending') {
                $res = $client->deactivateAuthorization($url);
                if (isset($res['status']) && $res['status'] === 'deactivated') {
                    $done++;
                } else {
                    $errors[] = isset($res['status']) ? $res['status'] : '?';
                }
            }
        } catch (Throwable $e) {
            $errors[] = $e->getMessage();
        }
    }
    check('autorisations en attente désactivées (' . $done . ' sur ' . count($authzToDeactivate) . ' relevées)',
        count($errors) === 0 && $done >= 1, implode(' ; ', $errors));
}

section('ZeroSSL (annuaire seulement, aucun compte créé)');
try {
    $z = new acmeClient(acmeClient::ZEROSSL, $accountKey, $logger);
    check('requiresEab() = true', $z->requiresEab() === true);
} catch (Throwable $e) {
    check('requiresEab() = true', false, $e->getMessage());
}

section('Journal');
$secretLeak = false;
foreach ($journal as $line) {
    if (strpos($line[1], 'PRIVATE KEY') !== false || strpos($line[1], '"protected"') !== false || strpos($line[1], '"signature"') !== false) {
        $secretLeak = true;
    }
}
check('aucune clé ni corps JWS dans le journal (' . count($journal) . ' lignes)', !$secretLeak);

echo "\n" . ($failures === 0
    ? 'RÉSULTAT : OK, ' . $count . ' vérifications'
    : 'RÉSULTAT : ÉCHEC, ' . $failures . ' sur ' . $count . ' vérifications') . ' (PHP ' . PHP_VERSION . ")\n";
exit($failures === 0 ? 0 : 1);

<?php
/* This file is part of the Jeedom acme plugin.
 * Copyright (C) sMug (Jérôme Fafchamps) — AGPL-3.0-or-later
 *
 * Test hors ligne de acmeProbe : un serveur TLS éphémère est monté en PHP sur
 * 127.0.0.1 (port aléatoire, processus fils), avec deux certificats
 * auto-signés choisis selon le SNI ; la sonde doit lire le bon numéro de
 * série, et renvoyer une erreur propre sur un port fermé ou un serveur muet.
 * Usage : php tests/test_probe.php
 * Code retour 0 si tout passe, 1 sinon.
 */

require_once __DIR__ . '/../core/class/acmeProbe.class.php';

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

/* Certificat auto-signé EC P-256 pour $name, de numéro de série $serial.
 * Renvoie [chemin du certificat, chemin de la clé]. */
function makeCert(string $dir, string $name, int $serial): array {
    $key = openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'));
    $conf = $dir . '/' . $name . '.cnf';
    file_put_contents($conf, "[req]\ndistinguished_name = dn\n[dn]\n[ext]\nsubjectAltName = DNS:" . $name . "\n");
    $options = array('config' => $conf, 'digest_alg' => 'sha256', 'x509_extensions' => 'ext');
    $csr = openssl_csr_new(array('commonName' => $name), $key, $options);
    $x509 = openssl_csr_sign($csr, null, $key, 30, $options, $serial);
    openssl_x509_export($x509, $certPem);
    openssl_pkey_export($key, $keyPem, null, array('config' => $conf));
    file_put_contents($dir . '/' . $name . '.crt', $certPem);
    file_put_contents($dir . '/' . $name . '.key', $keyPem);
    return array($dir . '/' . $name . '.crt', $dir . '/' . $name . '.key');
}

/* Port TCP libre sur 127.0.0.1 : on lie une socket au port 0, on lit le
 * port attribué, on la referme. */
function freePort(): int {
    $s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $name = stream_socket_get_name($s, false);
    fclose($s);
    return (int) substr($name, strrpos($name, ':') + 1);
}

function removeTree(string $dir): void {
    foreach ((array) @scandir($dir) as $entry) {
        if ($entry !== '.' && $entry !== '..' && $entry !== false) {
            @unlink($dir . '/' . $entry);
        }
    }
    @rmdir($dir);
}

if (!extension_loaded('openssl')) {
    echo "Extension openssl absente : test ignoré.\n";
    exit(0);
}

$dir = sys_get_temp_dir() . '/acme_probe_' . getmypid();
@mkdir($dir, 0700);
$process = null;
$pipes = array();

try {
    section('Normalisation');
    check('normalizeSerial : zéros de tête et minuscules', acmeProbe::normalizeSerial('00ab:cd:01') === 'ABCD01', acmeProbe::normalizeSerial('00ab:cd:01'));
    check('normalizeSerial : zéro', acmeProbe::normalizeSerial('000') === '0');
    check('serverName : sans « *. »', acmeProbe::serverName('*.Example.org.') === 'example.org');
    check('serverName : nom simple', acmeProbe::serverName('jeedom.example.org') === 'jeedom.example.org');

    /* Deux certificats, dont un numéro de série à bit de poids fort (openssl
     * le préfixe alors d'un 00 en DER) : la comparaison doit y survivre. */
    list($certA, $keyA) = makeCert($dir, 'a.test', 0x8ABC1234);
    list($certB, $keyB) = makeCert($dir, 'b.test', 0x1234);
    $parsedA = openssl_x509_parse(file_get_contents($certA));
    $expectedA = acmeProbe::normalizeSerial(isset($parsedA['serialNumberHex']) ? $parsedA['serialNumberHex'] : dechex((int) $parsedA['serialNumber']));
    check('certificat de test A : numéro de série attendu', $expectedA === '8ABC1234', $expectedA);

    /* Serveur TLS dans un processus fils : il annonce son port sur sa sortie
     * standard, puis accepte les connexions pendant au plus 60 s. Le
     * certificat est choisi selon le SNI (a.test par défaut). */
    $server = $dir . '/server.php';
    file_put_contents($server, '<?php
list(, $certA, $keyA, $certB, $keyB) = $argv;
$ctx = stream_context_create(array("ssl" => array(
    "local_cert" => $certA, "local_pk" => $keyA,
    "SNI_enabled" => true,
    "SNI_server_certs" => array(
        "a.test" => array("local_cert" => $certA, "local_pk" => $keyA),
        "b.test" => array("local_cert" => $certB, "local_pk" => $keyB),
    ),
)));
$srv = stream_socket_server("ssl://127.0.0.1:0", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if ($srv === false) { fwrite(STDOUT, "ERR " . $errstr . "\n"); exit(1); }
$name = stream_socket_get_name($srv, false);
fwrite(STDOUT, substr($name, strrpos($name, ":") + 1) . "\n");
fflush(STDOUT);
$end = time() + 60;
while (time() < $end) {
    $c = @stream_socket_accept($srv, 1);
    if ($c !== false) { @fclose($c); }
}
');
    $process = proc_open(array(PHP_BINARY, $server, $certA, $keyA, $certB, $keyB),
                         array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes);
    if (!is_resource($process)) {
        throw new Exception('proc_open impossible');
    }
    $read = array($pipes[1]);
    $write = null;
    $except = null;
    $line = '';
    if (stream_select($read, $write, $except, 10) > 0) {
        $line = trim((string) fgets($pipes[1]));
    }
    if (!ctype_digit($line)) {
        throw new Exception('Le serveur de test n\'a pas démarré : ' . $line . ' ' . stream_get_contents($pipes[2]));
    }
    $port = (int) $line;
    echo "\n(serveur TLS de test sur 127.0.0.1:" . $port . ")\n";

    $logs = array();
    $probe = new acmeProbe(function ($level, $message) use (&$logs) {
        $logs[] = $level . ' ' . $message;
    });

    section('Serveur TLS');
    $r = $probe->fetch('127.0.0.1', $port, 'a.test', 5);
    check('SNI a.test : lecture réussie', $r['ok'] === true, $r['error']);
    check('SNI a.test : numéro de série', $r['serial'] === '8ABC1234', $r['serial']);
    check('SNI a.test : noms du certificat', $r['domains'] === array('a.test'), implode(',', $r['domains']));
    check('SNI a.test : expiration lue', $r['notAfter'] > time());
    check('SNI a.test : erreur vide', $r['error'] === '');

    $r = $probe->fetch('127.0.0.1', $port, 'b.test', 5);
    check('SNI b.test : autre certificat servi', $r['ok'] && $r['serial'] === '1234', $r['serial'] . ' ' . $r['error']);

    $r = $probe->fetch('127.0.0.1', $port, '*.b.test', 5);
    check('Nom générique : SNI sans « *. »', $r['ok'] && $r['serial'] === '1234', $r['serial'] . ' ' . $r['error']);
    check('Journal appelé', count($logs) >= 3, (string) count($logs));

    section('Erreurs propres');
    $closed = freePort();
    $t = microtime(true);
    $r = $probe->fetch('127.0.0.1', $closed, 'a.test', 3);
    check('Port fermé : échec', $r['ok'] === false);
    check('Port fermé : message d\'erreur', $r['error'] !== '' && $r['serial'] === '', $r['error']);
    check('Port fermé : réponse immédiate', microtime(true) - $t < 2.5, round(microtime(true) - $t, 2) . ' s');

    /* Serveur muet : la connexion TCP aboutit (file d'attente du noyau), mais
     * personne ne répond à la négociation TLS. La sonde doit rendre la main
     * au bout du délai, pas rester bloquée. */
    $mute = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $muteName = stream_socket_get_name($mute, false);
    $mutePort = (int) substr($muteName, strrpos($muteName, ':') + 1);
    $t = microtime(true);
    $r = $probe->fetch('127.0.0.1', $mutePort, 'a.test', 1);
    $elapsed = microtime(true) - $t;
    fclose($mute);
    check('Serveur muet : échec', $r['ok'] === false, $r['error']);
    check('Serveur muet : délai respecté', $elapsed < 3, round($elapsed, 2) . ' s');

    $r = $probe->fetch('127.0.0.1', 0, 'a.test', 1);
    check('Port invalide : échec propre', $r['ok'] === false && $r['error'] !== '', $r['error']);
} catch (Throwable $e) {
    check('Exécution du test', false, get_class($e) . ' : ' . $e->getMessage());
} finally {
    if (is_resource($process)) {
        proc_terminate($process);
        foreach ($pipes as $pipe) {
            @fclose($pipe);
        }
        proc_close($process);
    }
    removeTree($dir);
}

echo "\n" . ($failures === 0
    ? 'RÉSULTAT : OK, ' . $count . ' vérifications'
    : 'RÉSULTAT : ÉCHEC, ' . $failures . ' sur ' . $count . ' vérifications') . ' (PHP ' . PHP_VERSION . ', ' . OPENSSL_VERSION_TEXT . ")\n";
exit($failures === 0 ? 0 : 1);

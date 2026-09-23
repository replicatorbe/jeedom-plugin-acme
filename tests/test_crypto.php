<?php
/* This file is part of the Jeedom acme plugin.
 * Copyright (C) sMug (Jérôme Fafchamps) — AGPL-3.0-or-later
 *
 * Test hors ligne de acmeCrypto : clés, JWK/empreinte, signatures JWS, CSR,
 * lecture de certificats.  Usage : php tests/test_crypto.php
 * Code retour 0 si tout passe, 1 sinon.
 */

require_once __DIR__ . '/../core/class/acmeCrypto.class.php';

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

/** Exécute $fn ; toute exception compte comme un échec, sans interrompre les autres tests. */
function guarded(string $label, callable $fn): void {
    try {
        $fn();
    } catch (Throwable $e) {
        check($label, false, get_class($e) . ' : ' . $e->getMessage());
    }
}

/* Encodage DER minimal, pour fabriquer une clé publique RSA à partir de n et e. */
function derLen(int $l): string {
    if ($l < 0x80) {
        return chr($l);
    }
    $b = ltrim(pack('N', $l), "\0");
    return chr(0x80 | strlen($b)) . $b;
}
function derTlv(int $tag, string $v): string {
    return chr($tag) . derLen(strlen($v)) . $v;
}
function derUint(string $bin): string {
    $bin = ltrim($bin, "\0");
    if ($bin === '' || (ord($bin[0]) & 0x80)) {
        $bin = "\0" . $bin;
    }
    return derTlv(0x02, $bin);
}
function rsaPublicPem(string $n, string $e): string {
    $algo = derTlv(0x30, derTlv(0x06, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") . "\x05\x00");
    $rsaKey = derTlv(0x30, derUint($n) . derUint($e));
    $spki = derTlv(0x30, $algo . derTlv(0x03, "\0" . $rsaKey));
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

/* ---------------------------------------------------------------------- */
section('Base64url');
guarded('b64url', function () {
    check('encodage sans remplissage', acmeCrypto::b64url("\xfb\xff\xfe") === '-__-');
    check('aller-retour', acmeCrypto::b64urlDecode(acmeCrypto::b64url("ab\x00\xff?")) === "ab\x00\xff?");
    check('décodage base64 classique accepté', acmeCrypto::b64urlDecode('+//+') === "\xfb\xff\xfe");
});

/* ---------------------------------------------------------------------- */
section('Génération des clés, JWK, algorithme, signature');
$keys = array();
$expect = array(
    'ec256' => array('ES256', 'EC', 'P-256', 64, OPENSSL_ALGO_SHA256),
    'ec384' => array('ES384', 'EC', 'P-384', 96, OPENSSL_ALGO_SHA384),
    'rsa2048' => array('RS256', 'RSA', null, 256, OPENSSL_ALGO_SHA256),
    'rsa4096' => array('RS256', 'RSA', null, 512, OPENSSL_ALGO_SHA256),
);
foreach ($expect as $type => $e) {
    guarded($type, function () use ($type, $e, &$keys) {
        $t = microtime(true);
        $pem = acmeCrypto::generateKey($type);
        $keys[$type] = $pem;
        check($type . ' : génération', strpos($pem, 'PRIVATE KEY-----') !== false, sprintf('%.2f s', microtime(true) - $t));
        check($type . ' : alg = ' . $e[0], acmeCrypto::alg($pem) === $e[0], acmeCrypto::alg($pem));
        $jwk = acmeCrypto::jwk($pem);
        $expectedKeys = $e[1] === 'EC' ? array('crv', 'kty', 'x', 'y') : array('e', 'kty', 'n');
        check($type . ' : membres JWK triés', array_keys($jwk) === $expectedKeys, implode(',', array_keys($jwk)));
        check($type . ' : kty', $jwk['kty'] === $e[1]);
        if ($e[1] === 'EC') {
            $size = $e[3] / 2;
            check($type . ' : crv ' . $e[2], $jwk['crv'] === $e[2]);
            check($type . ' : x et y sur ' . $size . ' octets',
                strlen(acmeCrypto::b64urlDecode($jwk['x'])) === $size && strlen(acmeCrypto::b64urlDecode($jwk['y'])) === $size);
        } else {
            check($type . ' : e = AQAB', $jwk['e'] === 'AQAB');
        }
        // L'empreinte calculée à partir de la clé publique est la même que depuis la clé privée.
        $pub = openssl_pkey_get_details(openssl_pkey_get_private($pem))['key'];
        check($type . ' : empreinte identique clé privée / publique', acmeCrypto::thumbprint($pem) === acmeCrypto::thumbprint($pub));
        check($type . ' : empreinte = 43 caractères b64url', (bool) preg_match('/^[A-Za-z0-9_-]{43}$/', acmeCrypto::thumbprint($pem)));

        // Signature : taille fixe, vérifiable par OpenSSL après reconversion en DER.
        $data = 'eyJhbGciOiJFUzI1NiJ9.' . acmeCrypto::b64url('charge utile ' . $type);
        $ok = true;
        $sizes = array();
        for ($i = 0; $i < 20; $i++) {    // plusieurs essais : R ou S ont parfois des zéros de tête
            $sig = acmeCrypto::sign($pem, $data . $i);
            $sizes[strlen($sig)] = true;
            $der = $e[1] === 'EC' ? acmeCrypto::rawToDer($sig) : $sig;
            if (openssl_verify($data . $i, $der, $pub, $e[4]) !== 1) {
                $ok = false;
            }
            if ($e[1] === 'RSA' && $i >= 2) {
                break;
            }
        }
        check($type . ' : signature de ' . $e[3] . ' octets', array_keys($sizes) === array($e[3]), implode(',', array_keys($sizes)));
        check($type . ' : signature vérifiée par openssl_verify', $ok);
        $bad = acmeCrypto::sign($pem, $data);
        $der = $e[1] === 'EC' ? acmeCrypto::rawToDer($bad) : $bad;
        check($type . ' : signature rejetée si données modifiées', openssl_verify($data . 'x', $der, $pub, $e[4]) === 0);
        while (openssl_error_string() !== false) {
        }
    });
}

guarded('conversion DER/R||S', function () {
    // R avec zéro de tête et bit haut : la conversion doit garder 32 octets exacts.
    $raw = str_repeat("\0", 1) . str_repeat("\x80", 31) . str_repeat("\x01", 32);
    check('DER -> R||S -> DER stable (zéros de tête, bit de signe)', acmeCrypto::derToRaw(acmeCrypto::rawToDer($raw), 32) === $raw);
});

/* ---------------------------------------------------------------------- */
section('Vecteur de la RFC 7638 §3.1');
guarded('RFC 7638', function () {
    $n = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
    $pem = rsaPublicPem(acmeCrypto::b64urlDecode($n), acmeCrypto::b64urlDecode('AQAB'));
    $jwk = acmeCrypto::jwk($pem);
    check('JWK reconstruit (n, e)', $jwk['n'] === $n && $jwk['e'] === 'AQAB');
    check('JSON canonique', acmeCrypto::jsonEncode($jwk) === '{"e":"AQAB","kty":"RSA","n":"' . $n . '"}');
    $tp = acmeCrypto::thumbprint($pem);
    check('empreinte = NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $tp === 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $tp);
});

/* ---------------------------------------------------------------------- */
section('CSR avec SAN');
$domains = array('jeedom.example.org', '*.example.org', 'www.example.org');
foreach (array('ec256', 'rsa2048') as $type) {
    guarded('CSR ' . $type, function () use ($type, $domains, &$keys) {
        if (!isset($keys[$type])) {
            throw new Exception('clé ' . $type . ' absente');
        }
        $before = glob(sys_get_temp_dir() . '/acme_csr_*');
        $der = acmeCrypto::csr($keys[$type], $domains);
        $after = glob(sys_get_temp_dir() . '/acme_csr_*');
        check('CSR ' . $type . ' : fichier temporaire supprimé', count($after) === count($before));
        check('CSR ' . $type . ' : DER (SEQUENCE)', strlen($der) > 100 && ord($der[0]) === 0x30);
        $pem = "-----BEGIN CERTIFICATE REQUEST-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE REQUEST-----\n";
        $subject = openssl_csr_get_subject($pem, true);
        check('CSR ' . $type . ' : CN = premier domaine', is_array($subject) && isset($subject['CN']) && $subject['CN'] === $domains[0],
            is_array($subject) ? json_encode($subject) : 'illisible');
        $pub = openssl_csr_get_public_key($pem);
        $pubDetails = $pub ? openssl_pkey_get_details($pub) : false;
        $keyDetails = openssl_pkey_get_details(openssl_pkey_get_private($keys[$type]));
        check('CSR ' . $type . ' : clé publique = celle de la clé', $pubDetails && $pubDetails['key'] === $keyDetails['key']);

        // Décodage indépendant par la commande openssl, si elle existe.
        $bin = trim((string) shell_exec('command -v openssl 2>/dev/null'));
        if ($bin === '') {
            echo "  (commande openssl absente : décodage textuel non vérifié)\n";
            return;
        }
        $tmp = tempnam(sys_get_temp_dir(), 'acme_test_');
        file_put_contents($tmp, $pem);
        $text = (string) shell_exec(escapeshellarg($bin) . ' req -in ' . escapeshellarg($tmp) . ' -noout -text -verify 2>&1');
        unlink($tmp);
        check('CSR ' . $type . ' : signature valide (openssl req -verify)', stripos($text, 'verify OK') !== false || stripos($text, 'Certificate request self-signature verify OK') !== false);
        $all = true;
        foreach ($domains as $d) {
            if (strpos($text, 'DNS:' . $d) === false) {
                $all = false;
            }
        }
        check('CSR ' . $type . ' : SAN = les 3 domaines, wildcard compris', $all);
        check('CSR ' . $type . ' : SHA-256', stripos($text, 'sha256') !== false);
    });
}
guarded('CSR nom long', function () use (&$keys) {
    $long = str_repeat('a', 60) . '.example.org';   // > 64 caractères : pas de CN
    $der = acmeCrypto::csr($keys['ec256'], array($long));
    $pem = "-----BEGIN CERTIFICATE REQUEST-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE REQUEST-----\n";
    $subject = openssl_csr_get_subject($pem, true);
    check('CSR nom > 64 caractères : acceptée, sans CN', is_array($subject) && !isset($subject['CN']));
});
guarded('CSR invalide', function () use (&$keys) {
    $thrown = false;
    try {
        acmeCrypto::csr($keys['ec256'], array('bad domain,DNS:evil.com'));
    } catch (Exception $e) {
        $thrown = true;
    }
    check('CSR : nom invalide refusé (pas d\'injection dans la configuration)', $thrown);
});

/* ---------------------------------------------------------------------- */
section('Certificat auto-signé : certInfo, keyMatchesCert, splitChain');
guarded('certificat', function () use (&$keys, $domains) {
    // Autorité de test puis certificat feuille signé par elle, avec SAN.
    $caKey = openssl_pkey_get_private($keys['ec384']);
    $caCsr = openssl_csr_new(array('commonName' => 'Autorite de test acme'), $caKey, array('digest_alg' => 'sha384'));
    $caCert = openssl_csr_sign($caCsr, null, $caKey, 30, array('digest_alg' => 'sha384'), 1);
    $caPem = '';
    openssl_x509_export($caCert, $caPem);

    $csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" . chunk_split(base64_encode(acmeCrypto::csr($keys['ec256'], $domains)), 64, "\n") . "-----END CERTIFICATE REQUEST-----\n";
    $cfg = tempnam(sys_get_temp_dir(), 'acme_test_');
    file_put_contents($cfg, "[ req ]\ndistinguished_name = dn\n[ dn ]\n[ ext ]\nsubjectAltName = DNS:" . implode(',DNS:', $domains) . "\n");
    $leaf = openssl_csr_sign($csrPem, $caPem, $caKey, 90, array('config' => $cfg, 'x509_extensions' => 'ext', 'digest_alg' => 'sha256'), 0x1234ABCD);
    unlink($cfg);
    $leafPem = '';
    openssl_x509_export($leaf, $leafPem);

    $info = acmeCrypto::certInfo($leafPem);
    check('certInfo : domaines (SAN)', $info['domains'] === $domains, implode(', ', $info['domains']));
    check('certInfo : émetteur', $info['issuer'] === 'Autorite de test acme', $info['issuer']);
    check('certInfo : numéro de série hexadécimal', ltrim($info['serial'], '0') === '1234ABCD', $info['serial']);
    check('certInfo : notAfter ≈ +90 j', abs($info['notAfter'] - (time() + 90 * 86400)) < 120);
    check('certInfo : notBefore ≈ maintenant', abs($info['notBefore'] - time()) < 120);
    check('certInfo : daysLeft = 89 ou 90', in_array($info['daysLeft'], array(89, 90), true), (string) $info['daysLeft']);

    check('keyMatchesCert : bonne clé', acmeCrypto::keyMatchesCert($keys['ec256'], $leafPem));
    check('keyMatchesCert : autre clé EC', !acmeCrypto::keyMatchesCert($keys['ec384'], $leafPem));
    check('keyMatchesCert : clé RSA', !acmeCrypto::keyMatchesCert($keys['rsa2048'], $leafPem));
    check('keyMatchesCert : clé illisible', !acmeCrypto::keyMatchesCert('pas une clé', $leafPem));

    $chain = acmeCrypto::splitChain("texte avant\n" . $leafPem . "\n\n" . str_replace("\n", "\r\n", $caPem) . "texte après");
    check('splitChain : 2 certificats', count($chain) === 2, (string) count($chain));
    check('splitChain : feuille en premier', count($chain) === 2 && acmeCrypto::certInfo($chain[0])['serial'] === $info['serial']);
    check('splitChain : PEM relisible', count($chain) === 2 && openssl_x509_parse($chain[1]) !== false);
    check('splitChain : chaîne vide', acmeCrypto::splitChain('rien') === array());
    check('certInfo sur une chaîne = la feuille', acmeCrypto::certInfo($leafPem . $caPem)['domains'] === $domains);
    check('keyMatchesCert sur une chaîne = la feuille', acmeCrypto::keyMatchesCert($keys['ec256'], $leafPem . $caPem));
});

/* ---------------------------------------------------------------------- */
echo "\n" . ($failures === 0
    ? 'RÉSULTAT : OK, ' . $count . ' vérifications'
    : 'RÉSULTAT : ÉCHEC, ' . $failures . ' sur ' . $count . ' vérifications') . ' (PHP ' . PHP_VERSION . ', ' . OPENSSL_VERSION_TEXT . ")\n";
exit($failures === 0 ? 0 : 1);

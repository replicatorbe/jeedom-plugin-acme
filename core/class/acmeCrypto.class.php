<?php
/* This file is part of the Jeedom acme plugin.
 *
 * Copyright (C) sMug (Jérôme Fafchamps)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Primitives cryptographiques du client ACME : clés, JWK (RFC 7517/7638),
 * signatures JWS (RFC 7515/7518), CSR avec SAN, lecture de certificats.
 *
 * Aucune dépendance hors de l'extension openssl, aucune classe du cœur de
 * Jeedom : la classe se teste en ligne de commande (tests/test_crypto.php).
 * Compatible PHP 7.4 à 8.4 (ressources OpenSSL en 7.4, objets en 8.x : le
 * code ne fait jamais la différence et n'appelle pas openssl_*_free, déprécié).
 *
 * Toute erreur lève une Exception ; acmeClient la convertit si besoin.
 */
class acmeCrypto {

    /* Types de clé acceptés => paramètres de openssl_pkey_new. */
    const KEY_TYPES = array(
        'ec256' => array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'),
        'ec384' => array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1'),
        'rsa2048' => array('private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048),
        'rsa4096' => array('private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096),
    );

    /* Courbes prises en charge : nom OpenSSL => [crv JWK, alg JWS, taille d'une coordonnée en octets, hachage]. */
    const CURVES = array(
        'prime256v1' => array('P-256', 'ES256', 32, OPENSSL_ALGO_SHA256),
        'secp384r1' => array('P-384', 'ES384', 48, OPENSSL_ALGO_SHA384),
    );

    /* ------------------------------------------------------------------ */
    /* Clés                                                                */
    /* ------------------------------------------------------------------ */

    /**
     * Génère une clé privée et la renvoie au format PEM (non chiffrée).
     * Types : 'ec256' (défaut), 'ec384', 'rsa2048', 'rsa4096'.
     */
    public static function generateKey(string $type = 'ec256'): string {
        if (!isset(self::KEY_TYPES[$type])) {
            throw new Exception('Type de clé inconnu : ' . $type);
        }
        $key = openssl_pkey_new(self::KEY_TYPES[$type]);
        if ($key === false) {
            throw new Exception('Échec de la génération de la clé ' . $type . ' : ' . self::opensslErrors());
        }
        $pem = '';
        if (!openssl_pkey_export($key, $pem)) {
            throw new Exception('Échec de l\'export de la clé ' . $type . ' : ' . self::opensslErrors());
        }
        return $pem;
    }

    /* ------------------------------------------------------------------ */
    /* Base64url (RFC 4648 §5, sans remplissage)                           */
    /* ------------------------------------------------------------------ */

    public static function b64url(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Décode du base64url ; accepte aussi le base64 classique (certaines
     * autorités fournissent la clé HMAC EAB avec « + » et « / »).
     */
    public static function b64urlDecode(string $data): string {
        $data = strtr(trim($data), '-_', '+/');
        $pad = strlen($data) % 4;
        if ($pad) {
            $data .= str_repeat('=', 4 - $pad);
        }
        $out = base64_decode($data, true);
        if ($out === false) {
            throw new Exception('Donnée base64url invalide');
        }
        return $out;
    }

    /* ------------------------------------------------------------------ */
    /* JWK et empreinte                                                    */
    /* ------------------------------------------------------------------ */

    /**
     * Clé publique au format JWK, limitée aux membres obligatoires et triée
     * dans l'ordre lexicographique exigé pour l'empreinte (RFC 7638 §3.2).
     * Accepte une clé privée ou une clé publique PEM.
     */
    public static function jwk(string $keyPem): array {
        $d = self::details($keyPem);
        if ($d['type'] === OPENSSL_KEYTYPE_RSA) {
            return array(
                'e' => self::b64url(ltrim($d['rsa']['e'], "\0")),
                'kty' => 'RSA',
                'n' => self::b64url(ltrim($d['rsa']['n'], "\0")),
            );
        }
        if ($d['type'] === OPENSSL_KEYTYPE_EC) {
            $curve = self::curve($d);
            $size = $curve[2];
            return array(
                'crv' => $curve[0],
                'kty' => 'EC',
                // OpenSSL peut omettre les zéros de tête : on remet la taille fixe.
                'x' => self::b64url(self::padLeft($d['ec']['x'], $size)),
                'y' => self::b64url(self::padLeft($d['ec']['y'], $size)),
            );
        }
        throw new Exception('Type de clé non pris en charge (RSA ou EC P-256/P-384 attendu)');
    }

    /** Empreinte JWK (RFC 7638) : b64url(sha256(JSON canonique du JWK)). */
    public static function thumbprint(string $keyPem): string {
        return self::b64url(hash('sha256', self::jsonEncode(self::jwk($keyPem)), true));
    }

    /** Algorithme JWS correspondant à la clé : 'ES256', 'ES384' ou 'RS256'. */
    public static function alg(string $keyPem): string {
        $d = self::details($keyPem);
        if ($d['type'] === OPENSSL_KEYTYPE_RSA) {
            return 'RS256';
        }
        if ($d['type'] === OPENSSL_KEYTYPE_EC) {
            return self::curve($d)[1];
        }
        throw new Exception('Type de clé non pris en charge (RSA ou EC P-256/P-384 attendu)');
    }

    /* ------------------------------------------------------------------ */
    /* Signature JWS                                                       */
    /* ------------------------------------------------------------------ */

    /**
     * Signature brute au sens JWS de $data. Pour EC, OpenSSL produit une
     * structure DER SEQUENCE { INTEGER r, INTEGER s } que JWS n'accepte pas :
     * elle est convertie en R||S, chaque moitié sur la taille fixe de la courbe.
     */
    public static function sign(string $keyPem, string $data): string {
        $key = openssl_pkey_get_private($keyPem);
        if ($key === false) {
            throw new Exception('Clé privée illisible : ' . self::opensslErrors());
        }
        $d = openssl_pkey_get_details($key);
        if ($d === false) {
            throw new Exception('Clé privée illisible : ' . self::opensslErrors());
        }
        if ($d['type'] === OPENSSL_KEYTYPE_RSA) {
            $sig = '';
            if (!openssl_sign($data, $sig, $key, OPENSSL_ALGO_SHA256)) {
                throw new Exception('Échec de la signature RS256 : ' . self::opensslErrors());
            }
            return $sig;
        }
        if ($d['type'] === OPENSSL_KEYTYPE_EC) {
            $curve = self::curve($d);
            $der = '';
            if (!openssl_sign($data, $der, $key, $curve[3])) {
                throw new Exception('Échec de la signature ' . $curve[1] . ' : ' . self::opensslErrors());
            }
            return self::derToRaw($der, $curve[2]);
        }
        throw new Exception('Type de clé non pris en charge pour la signature');
    }

    /** Convertit une signature ECDSA DER en R||S de 2 × $size octets. */
    public static function derToRaw(string $der, int $size): string {
        $pos = 0;
        if (self::derReadTag($der, $pos) !== 0x30) {
            throw new Exception('Signature ECDSA DER invalide (SEQUENCE attendue)');
        }
        self::derReadLength($der, $pos);
        $out = '';
        for ($i = 0; $i < 2; $i++) {
            if (self::derReadTag($der, $pos) !== 0x02) {
                throw new Exception('Signature ECDSA DER invalide (INTEGER attendu)');
            }
            $len = self::derReadLength($der, $pos);
            $int = ltrim((string) substr($der, $pos, $len), "\0");
            $pos += $len;
            if (strlen($int) > $size) {
                throw new Exception('Signature ECDSA DER invalide (entier trop long)');
            }
            $out .= self::padLeft($int, $size);
        }
        return $out;
    }

    /** Opération inverse de derToRaw (utile aux tests : openssl_verify attend du DER). */
    public static function rawToDer(string $raw): string {
        $half = intdiv(strlen($raw), 2);
        $seq = '';
        foreach (array(substr($raw, 0, $half), substr($raw, $half)) as $int) {
            $int = ltrim($int, "\0");
            if ($int === '' || (ord($int[0]) & 0x80)) {
                $int = "\0" . $int;   // entier positif : octet nul si le bit de poids fort est à 1
            }
            $seq .= "\x02" . self::derLength(strlen($int)) . $int;
        }
        return "\x30" . self::derLength(strlen($seq)) . $seq;
    }

    /* ------------------------------------------------------------------ */
    /* CSR                                                                 */
    /* ------------------------------------------------------------------ */

    /**
     * Demande de signature de certificat, au format DER (ce qu'attend ACME).
     * SAN = tous les domaines ; CN = le premier s'il tient en 64 caractères
     * (limite X.509), sinon pas de CN (accepté par les autorités ACME).
     *
     * openssl_csr_new ne sait poser des extensions que via un fichier de
     * configuration : on en écrit un temporaire, minimal et autosuffisant
     * (aucun appel au openssl.cnf du système), valable en OpenSSL 1.1 et 3.x.
     */
    public static function csr(string $keyPem, array $domains): string {
        $domains = array_values(array_unique(array_filter(array_map(function ($d) {
            return strtolower(trim((string) $d));
        }, $domains), 'strlen')));
        if (count($domains) === 0) {
            throw new Exception('Aucun domaine pour la demande de certificat');
        }
        $san = array();
        foreach ($domains as $domain) {
            if (!preg_match('/^(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?$/', $domain)) {
                throw new Exception('Nom de domaine invalide : ' . $domain);
            }
            $san[] = 'DNS:' . $domain;
        }
        $key = openssl_pkey_get_private($keyPem);
        if ($key === false) {
            throw new Exception('Clé du certificat illisible : ' . self::opensslErrors());
        }

        $config = "# Fichier temporaire du plugin Jeedom acme\n"
            . "[ req ]\n"
            . "distinguished_name = req_dn\n"
            . "req_extensions = v3_req\n"
            . "prompt = no\n"
            . "[ req_dn ]\n"
            . "[ v3_req ]\n"
            . "subjectAltName = " . implode(',', $san) . "\n";
        $tmp = tempnam(sys_get_temp_dir(), 'acme_csr_');
        if ($tmp === false) {
            throw new Exception('Impossible de créer le fichier de configuration temporaire de la CSR');
        }
        try {
            if (file_put_contents($tmp, $config) === false) {
                throw new Exception('Impossible d\'écrire le fichier de configuration temporaire de la CSR');
            }
            $dn = array();
            if (strlen($domains[0]) <= 64) {
                $dn['commonName'] = $domains[0];
            }
            $options = array(
                'config' => $tmp,
                'digest_alg' => 'sha256',
                'req_extensions' => 'v3_req',
            );
            $csr = openssl_csr_new($dn, $key, $options);
            if ($csr === false || $csr === true) {
                throw new Exception('Échec de la création de la CSR : ' . self::opensslErrors());
            }
            $pem = '';
            if (!openssl_csr_export($csr, $pem)) {
                throw new Exception('Échec de l\'export de la CSR : ' . self::opensslErrors());
            }
        } finally {
            @unlink($tmp);
        }
        return self::pemToDer($pem);
    }

    /* ------------------------------------------------------------------ */
    /* Certificats                                                         */
    /* ------------------------------------------------------------------ */

    /**
     * Informations utiles d'un certificat (le premier si $certPem est une chaîne) :
     * ['notBefore' => int, 'notAfter' => int, 'domains' => string[], 'issuer' => string,
     *  'serial' => string (hex), 'daysLeft' => int]
     */
    public static function certInfo(string $certPem): array {
        $chain = self::splitChain($certPem);
        if (count($chain) === 0) {
            throw new Exception('Aucun certificat PEM trouvé');
        }
        $x = openssl_x509_parse($chain[0]);
        if ($x === false) {
            throw new Exception('Certificat illisible : ' . self::opensslErrors());
        }
        $domains = array();
        if (isset($x['extensions']['subjectAltName'])) {
            foreach (explode(',', $x['extensions']['subjectAltName']) as $entry) {
                $entry = trim($entry);
                if (stripos($entry, 'DNS:') === 0) {
                    $domains[] = substr($entry, 4);
                }
            }
        }
        if (count($domains) === 0 && isset($x['subject']['CN'])) {
            $domains[] = is_array($x['subject']['CN']) ? end($x['subject']['CN']) : $x['subject']['CN'];
        }
        $issuer = '';
        foreach (array('CN', 'O') as $field) {
            if (isset($x['issuer'][$field])) {
                $issuer = is_array($x['issuer'][$field]) ? end($x['issuer'][$field]) : $x['issuer'][$field];
                break;
            }
        }
        $notAfter = (int) $x['validTo_time_t'];
        $serial = isset($x['serialNumberHex']) ? $x['serialNumberHex'] : self::decToHex((string) $x['serialNumber']);
        return array(
            'notBefore' => (int) $x['validFrom_time_t'],
            'notAfter' => $notAfter,
            'domains' => $domains,
            'issuer' => (string) $issuer,
            'serial' => strtoupper((string) $serial),
            'daysLeft' => (int) floor(($notAfter - time()) / 86400),
        );
    }

    /** Découpe une chaîne PEM en certificats, dans l'ordre du fichier (feuille en premier chez ACME). */
    public static function splitChain(string $pem): array {
        $out = array();
        if (preg_match_all('/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+\/=\s]+?)\s*-----END CERTIFICATE-----/', $pem, $m)) {
            foreach ($m[1] as $body) {
                $b64 = preg_replace('/\s+/', '', $body);
                $out[] = "-----BEGIN CERTIFICATE-----\n" . chunk_split($b64, 64, "\n") . "-----END CERTIFICATE-----\n";
            }
        }
        return $out;
    }

    /** Vrai si la clé privée correspond à la clé publique du certificat (le premier de la chaîne). */
    public static function keyMatchesCert(string $keyPem, string $certPem): bool {
        $chain = self::splitChain($certPem);
        if (count($chain) === 0) {
            return false;
        }
        $key = @openssl_pkey_get_private($keyPem);
        if ($key === false) {
            self::opensslErrors();
            return false;
        }
        $ok = @openssl_x509_check_private_key($chain[0], $key);
        self::opensslErrors();
        return $ok === true;
    }

    /* ------------------------------------------------------------------ */
    /* Outils internes                                                     */
    /* ------------------------------------------------------------------ */

    /** PEM (premier bloc) vers DER. */
    public static function pemToDer(string $pem): string {
        if (!preg_match('/-----BEGIN [A-Z0-9 ]+-----(.+?)-----END [A-Z0-9 ]+-----/s', $pem, $m)) {
            throw new Exception('Bloc PEM introuvable');
        }
        $der = base64_decode(preg_replace('/\s+/', '', $m[1]), true);
        if ($der === false) {
            throw new Exception('Bloc PEM invalide');
        }
        return $der;
    }

    /** JSON compact, sans échappement des « / » ni de l'Unicode (forme canonique JWS/JWK). */
    public static function jsonEncode($value): string {
        $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new Exception('Échec de l\'encodage JSON : ' . json_last_error_msg());
        }
        return $json;
    }

    /** Détails OpenSSL d'une clé privée ou publique PEM. */
    private static function details(string $keyPem): array {
        $key = @openssl_pkey_get_private($keyPem);
        if ($key === false) {
            $key = @openssl_pkey_get_public($keyPem);
        }
        if ($key === false) {
            throw new Exception('Clé illisible : ' . self::opensslErrors());
        }
        $d = openssl_pkey_get_details($key);
        self::opensslErrors();
        if ($d === false) {
            throw new Exception('Clé illisible');
        }
        return $d;
    }

    /** Paramètres de la courbe d'une clé EC, ou exception si la courbe n'est pas prise en charge. */
    private static function curve(array $details): array {
        $name = isset($details['ec']['curve_name']) ? $details['ec']['curve_name'] : '';
        if (!isset(self::CURVES[$name])) {
            throw new Exception('Courbe elliptique non prise en charge : ' . ($name === '' ? '?' : $name));
        }
        return self::CURVES[$name];
    }

    private static function padLeft(string $bin, int $size): string {
        return str_pad($bin, $size, "\0", STR_PAD_LEFT);
    }

    private static function derReadTag(string $der, int &$pos): int {
        if ($pos >= strlen($der)) {
            throw new Exception('Structure DER tronquée');
        }
        return ord($der[$pos++]);
    }

    private static function derReadLength(string $der, int &$pos): int {
        $len = self::derReadTag($der, $pos);
        if ($len & 0x80) {
            $n = $len & 0x7f;
            if ($n < 1 || $n > 4) {
                throw new Exception('Longueur DER invalide');
            }
            $len = 0;
            for ($i = 0; $i < $n; $i++) {
                $len = ($len << 8) | self::derReadTag($der, $pos);
            }
        }
        if ($pos + $len > strlen($der)) {
            throw new Exception('Structure DER tronquée');
        }
        return $len;
    }

    private static function derLength(int $len): string {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = ltrim(pack('N', $len), "\0");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /** Numéro de série décimal (anciens PHP sans serialNumberHex) vers hexadécimal. */
    private static function decToHex(string $dec): string {
        if (stripos($dec, '0x') === 0) {
            return substr($dec, 2);
        }
        $hex = '';
        while ($dec !== '' && $dec !== '0') {
            $rem = 0;
            $quot = '';
            for ($i = 0, $n = strlen($dec); $i < $n; $i++) {
                $cur = $rem * 10 + (int) $dec[$i];
                $q = intdiv($cur, 16);
                $rem = $cur % 16;
                if ($quot !== '' || $q > 0) {
                    $quot .= (string) $q;
                }
            }
            $hex = dechex($rem) . $hex;
            $dec = $quot;
        }
        return $hex === '' ? '0' : $hex;
    }

    /** Vide la file d'erreurs OpenSSL (sinon elle pollue les appels suivants) et la renvoie. */
    private static function opensslErrors(): string {
        $errors = array();
        while (($e = openssl_error_string()) !== false) {
            $errors[] = $e;
        }
        return count($errors) ? implode(' ; ', $errors) : 'erreur OpenSSL inconnue';
    }
}

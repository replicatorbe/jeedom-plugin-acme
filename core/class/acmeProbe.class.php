<?php
/* This file is part of Jeedom.
 *
 * Jeedom is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Jeedom is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Jeedom. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Sonde TLS : quel certificat le serveur web sert-il réellement ?
 *
 * Le plugin sait ce qu'il a installé, pas ce que le serveur répond : un autre
 * vhost qui passe devant, une installation restaurée, un Apache pas rechargé…
 * On se connecte donc comme un navigateur, avec l'indication de nom (SNI), et
 * on lit le numéro de série du certificat présenté.
 *
 * Aucune dépendance à Jeedom (voir CONCEPTION.md) : journal passé sous la
 * forme d'un callable function (string $level, string $message), testable en
 * ligne de commande (tests/test_probe.php). Ne lève jamais : le résultat porte
 * son erreur.
 */

class acmeProbe {

    /* Délai maximal par défaut (connexion + négociation TLS), en secondes. */
    const DEFAULT_TIMEOUT = 5.0;

    /** @var callable|null */
    private $logger;

    public function __construct(?callable $logger = null) {
        $this->logger = $logger;
    }

    private function log(string $level, string $message): void {
        if ($this->logger !== null) {
            call_user_func($this->logger, $level, $message);
        }
    }

    /* Numéro de série comparable : hexadécimal majuscule, sans séparateur ni
     * zéro de tête (même forme que acmeCrypto::certInfo, zéros en moins :
     * openssl ajoute un 00 quand le premier octet a son bit de poids fort). */
    public static function normalizeSerial(string $serial): string {
        $hex = strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', $serial));
        $hex = ltrim($hex, '0');
        return ($hex === '') ? '0' : $hex;
    }

    /* Nom à annoncer en SNI : le nom principal, sans le préfixe « *. » d'un
     * nom générique (un SNI ne peut pas contenir d'astérisque). */
    public static function serverName(string $domain): string {
        $name = strtolower(rtrim(trim($domain), '.'));
        if (strpos($name, '*.') === 0) {
            $name = substr($name, 2);
        }
        return $name;
    }

    /*
     * Se connecte en TLS à $host:$port en annonçant $serverName, et décrit le
     * certificat présenté. Ne lève jamais. Renvoie :
     *   ['ok' => bool, 'serial' => string (normalisé, vide en cas d'échec),
     *    'domains' => string[], 'issuer' => string, 'notAfter' => int,
     *    'error' => string (vide si ok), 'elapsed' => float (s)]
     *
     * Aucune vérification de la chaîne ni du nom (verify_peer à false) : on
     * veut lire le certificat servi, quel qu'il soit, et le comparer
     * nous-mêmes — un certificat expiré ou d'un autre nom est justement ce
     * qu'il faut voir.
     */
    public function fetch(string $host, int $port, string $serverName, float $timeout = self::DEFAULT_TIMEOUT): array {
        $result = array('ok' => false, 'serial' => '', 'domains' => array(), 'issuer' => '',
                        'notAfter' => 0, 'error' => '', 'elapsed' => 0.0);
        $start = microtime(true);
        try {
            $this->doFetch($host, $port, self::serverName($serverName), max(0.2, $timeout), $result);
        } catch (Throwable $e) {
            $result['ok'] = false;
            $result['error'] = $e->getMessage();
        }
        $result['elapsed'] = round(microtime(true) - $start, 3);
        if ($result['ok']) {
            $this->log('debug', 'Sonde TLS ' . $host . ':' . $port . ' (' . $serverName . ') : numéro de série ' . $result['serial']);
        } else {
            $this->log('debug', 'Sonde TLS ' . $host . ':' . $port . ' (' . $serverName . ') : ' . $result['error']);
        }
        return $result;
    }

    private function doFetch(string $host, int $port, string $sni, float $timeout, array &$result): void {
        if ($port < 1 || $port > 65535) {
            throw new Exception('Port invalide : ' . $port);
        }
        if (!extension_loaded('openssl')) {
            throw new Exception('Extension PHP openssl absente');
        }
        $ssl = array(
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'SNI_enabled' => true,
        );
        if ($sni !== '' && filter_var($sni, FILTER_VALIDATE_IP) === false) {
            $ssl['peer_name'] = $sni;
        }
        $context = stream_context_create(array('ssl' => $ssl));
        $address = (strpos($host, ':') !== false && substr($host, 0, 1) !== '[') ? '[' . $host . ']' : $host;

        /* Connexion TCP d'abord, puis négociation TLS en mode non bloquant :
         * c'est la seule façon de borner la négociation. En mode bloquant
         * (ssl:// direct), un serveur qui accepte la connexion sans jamais
         * répondre tiendrait la sonde indéfiniment ; en non bloquant, PHP
         * applique le délai de connexion à toute la négociation. */
        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client('tcp://' . $address . ':' . $port, $errno, $errstr, $timeout,
                                    STREAM_CLIENT_CONNECT, $context);
        if ($fp === false) {
            throw new Exception('Connexion impossible à ' . $host . ':' . $port
                . ($errstr !== '' ? ' : ' . $errstr : '') . ($errno ? ' (' . $errno . ')' : ''));
        }
        try {
            stream_set_timeout($fp, (int) ceil($timeout));
            stream_set_blocking($fp, false);
            $method = STREAM_CRYPTO_METHOD_TLS_CLIENT;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) {
                $method |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            }
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                $method |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            }
            $deadline = microtime(true) + $timeout;
            $lastError = '';
            set_error_handler(function ($severity, $message) use (&$lastError) {
                $lastError = preg_replace('/^stream_socket_enable_crypto\(\):\s*/', '', (string) $message);
                return true;
            });
            try {
                do {
                    $done = stream_socket_enable_crypto($fp, true, $method);
                    if ($done === 0) {
                        /* Négociation pas finie (anciens PHP en non bloquant) :
                         * on attend que la socket bouge, sans dépasser le délai. */
                        $read = array($fp);
                        $write = null;
                        $except = null;
                        $left = $deadline - microtime(true);
                        if ($left <= 0) {
                            break;
                        }
                        @stream_select($read, $write, $except, 0, (int) min(200000, $left * 1000000));
                    }
                } while ($done === 0 && microtime(true) < $deadline);
            } finally {
                restore_error_handler();
            }
            if ($done !== true) {
                throw new Exception('Négociation TLS en échec avec ' . $host . ':' . $port
                    . ($lastError !== '' ? ' : ' . $lastError : ($done === 0 ? ' : délai dépassé' : '')));
            }
            $params = stream_context_get_params($fp);
            $peer = isset($params['options']['ssl']['peer_certificate']) ? $params['options']['ssl']['peer_certificate'] : null;
            if ($peer === null || $peer === false) {
                throw new Exception('Le serveur ' . $host . ':' . $port . ' n\'a présenté aucun certificat');
            }
            $x = openssl_x509_parse($peer);
            if (!is_array($x)) {
                throw new Exception('Certificat présenté illisible');
            }
            $serial = isset($x['serialNumberHex']) ? (string) $x['serialNumberHex'] : self::decToHex((string) $x['serialNumber']);
            $result['serial'] = self::normalizeSerial($serial);
            $result['domains'] = self::domainsOf($x);
            $result['issuer'] = self::issuerOf($x);
            $result['notAfter'] = isset($x['validTo_time_t']) ? (int) $x['validTo_time_t'] : 0;
            $result['ok'] = true;
        } finally {
            @fclose($fp);
        }
    }

    /* Noms du certificat : SAN, sinon CN. */
    private static function domainsOf(array $x): array {
        $domains = array();
        if (!empty($x['extensions']['subjectAltName'])) {
            foreach (explode(',', (string) $x['extensions']['subjectAltName']) as $entry) {
                $entry = trim($entry);
                if (stripos($entry, 'DNS:') === 0) {
                    $domains[] = strtolower(trim(substr($entry, 4)));
                }
            }
        }
        if (count($domains) === 0 && !empty($x['subject']['CN'])) {
            $cn = $x['subject']['CN'];
            $domains[] = strtolower(is_array($cn) ? (string) reset($cn) : (string) $cn);
        }
        return $domains;
    }

    /* Émetteur : CN, sinon O (comme acmeCrypto::certInfo). */
    private static function issuerOf(array $x): string {
        foreach (array('CN', 'O') as $field) {
            if (isset($x['issuer'][$field])) {
                return (string) (is_array($x['issuer'][$field]) ? end($x['issuer'][$field]) : $x['issuer'][$field]);
            }
        }
        return '';
    }

    /* Numéro de série décimal (anciens PHP sans serialNumberHex) vers hexadécimal. */
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
                $digit = intdiv($cur, 16);
                $rem = $cur % 16;
                if ($quot !== '' || $digit > 0) {
                    $quot .= (string) $digit;
                }
            }
            $hex = dechex($rem) . $hex;
            $dec = $quot;
        }
        return ($hex === '') ? '0' : $hex;
    }
}

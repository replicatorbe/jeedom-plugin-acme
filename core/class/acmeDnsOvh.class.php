<?php
/* This file is part of the Jeedom acme plugin.
 *
 * Auteur : sMug (Jérôme Fafchamps)
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
 * Fournisseur DNS OVHcloud (API v1, signature « $1$ »).
 *
 * Droits nécessaires sur le jeton : GET/POST/DELETE /domain/zone/*
 * (GET /domain/zone en plus permet de lister les zones ; sans lui, la zone
 * est trouvée en sondant GET /domain/zone/<suffixe>).
 * Aucune dépendance au cœur de Jeedom ; les erreurs lèvent acmeException.
 */

require_once __DIR__ . '/acmeDns.class.php';

class acmeDnsOvh implements acmeDnsProvider {

    const ENDPOINTS = array(
        'ovh-eu' => 'https://eu.api.ovh.com/1.0',
        'ovh-ca' => 'https://ca.api.ovh.com/1.0',
        'ovh-us' => 'https://api.us.ovhcloud.com/1.0',
        'kimsufi-eu' => 'https://eu.api.kimsufi.com/1.0',
        'kimsufi-ca' => 'https://ca.api.kimsufi.com/1.0',
        'soyoustart-eu' => 'https://eu.api.soyoustart.com/1.0',
        'soyoustart-ca' => 'https://ca.api.soyoustart.com/1.0',
    );

    const ENDPOINT_LABELS = array(
        'ovh-eu' => 'OVHcloud Europe',
        'ovh-ca' => 'OVHcloud Canada / Asie-Pacifique',
        'ovh-us' => 'OVHcloud US',
        'kimsufi-eu' => 'Kimsufi Europe',
        'kimsufi-ca' => 'Kimsufi Canada',
        'soyoustart-eu' => 'So you Start Europe',
        'soyoustart-ca' => 'So you Start Canada',
    );

    const TTL = 60;

    /** @var string */
    protected $endpoint;
    /** @var string */
    protected $baseUrl;
    /** @var string */
    protected $applicationKey;
    /** @var string */
    protected $applicationSecret;
    /** @var string */
    protected $consumerKey;

    /** @var callable|null */
    protected $logger = null;

    /** @var callable|null transport injecté (tests) */
    protected $transport = null;

    /* Décalage horloge serveur - horloge locale, en secondes (null = inconnu). */
    protected $timeDelta = null;

    /* Liste des zones du compte (cache), null = pas encore lue. */
    protected $zones = null;

    /* Cache fqdn => ['zone' => ..., 'sub' => ...]. */
    protected $zoneCache = array();

    /* Enregistrements créés : liste de ['zone', 'sub', 'value', 'id']. */
    protected $created = array();

    /* Zones modifiées depuis le dernier commit (zone => true). */
    protected $touched = array();

    /* TXT lus par listTxt() : « zone|sub » => [id => cible brute]. */
    protected $listed = array();

    public function __construct(array $config, ?callable $logger = null) {
        $this->logger = $logger;
        $endpoint = isset($config['endpoint']) && trim((string) $config['endpoint']) !== ''
            ? trim((string) $config['endpoint']) : 'ovh-eu';
        $this->endpoint = $endpoint;
        $this->baseUrl = self::endpointUrl($endpoint);
        $this->applicationKey = isset($config['application_key']) ? trim((string) $config['application_key']) : '';
        $this->applicationSecret = isset($config['application_secret']) ? trim((string) $config['application_secret']) : '';
        $this->consumerKey = isset($config['consumer_key']) ? trim((string) $config['consumer_key']) : '';
    }

    public static function getLabel(): string {
        return 'OVHcloud';
    }

    public static function getFields(): array {
        return array(
            'endpoint' => array(
                'label' => "Point d'accès de l'API",
                'type' => 'select',
                'options' => self::ENDPOINT_LABELS,
                'default' => 'ovh-eu',
                'help' => "Région du compte qui gère la zone DNS. Pour un domaine chez OVHcloud en Europe : OVHcloud Europe.",
            ),
            'application_key' => array(
                'label' => 'Application key',
                'type' => 'text',
                'default' => '',
                'help' => "Clé d'application (AK), obtenue avec le bouton « Créer un jeton OVH » (page createToken d'OVHcloud).",
            ),
            'application_secret' => array(
                'label' => 'Application secret',
                'type' => 'password',
                'default' => '',
                'help' => "Secret de l'application (AS), affiché une seule fois à la création du jeton.",
            ),
            'consumer_key' => array(
                'label' => 'Consumer key',
                'type' => 'password',
                'default' => '',
                'help' => "Jeton d'accès (CK). Droits suffisants : GET, POST et DELETE sur /domain/zone/*. "
                    . "Validité : Illimitée (sinon les renouvellements automatiques échoueront à l'expiration du jeton).",
            ),
        );
    }

    /* URL de base (…/1.0) d'un point d'accès : identifiant connu ou URL https. */
    public static function endpointUrl(string $endpoint): string {
        if (isset(self::ENDPOINTS[$endpoint])) {
            return self::ENDPOINTS[$endpoint];
        }
        if (preg_match('#^https://[a-z0-9.-]+(/[A-Za-z0-9._/-]*)?$#i', $endpoint)) {
            return rtrim($endpoint, '/');
        }
        throw new acmeException("Point d'accès OVH inconnu : " . $endpoint
            . ' (connus : ' . implode(', ', array_keys(self::ENDPOINTS)) . ')');
    }

    /*
     * URL de la page OVHcloud qui crée d'un coup l'application et le jeton,
     * avec les droits préremplis. La page (https://<hôte>/createToken/)
     * redirige vers la connexion au compte en conservant les paramètres
     * GET=, POST=, DELETE= (répétables).
     */
    public static function createTokenUrl(string $endpoint): string {
        $base = self::endpointUrl($endpoint);
        $parts = parse_url($base);
        $host = isset($parts['host']) ? $parts['host'] : 'eu.api.ovh.com';
        return 'https://' . $host . '/createToken/'
            . '?GET=/domain/zone'
            . '&GET=/domain/zone/*'
            . '&POST=/domain/zone/*'
            . '&DELETE=/domain/zone/*';
    }

    /* Signature OVH : "$1$" . sha1(AS+CK+METHOD+URL+BODY+TSTAMP). */
    public static function signature(string $applicationSecret, string $consumerKey, string $method,
                                     string $url, string $body, int $timestamp): string {
        return '$1$' . sha1($applicationSecret . '+' . $consumerKey . '+' . strtoupper($method) . '+'
            . $url . '+' . $body . '+' . $timestamp);
    }

    /* Transport HTTP de remplacement (tests) :
     * function (string $method, string $url, array $headers, string $body): array
     * renvoyant ['code' => int, 'body' => string, 'error' => string]. */
    public function setTransport(?callable $transport): void {
        $this->transport = $transport;
    }

    public function test(): string {
        $this->requireCredentials();
        $lines = array();
        $lines[] = "Point d'accès : " . $this->endpoint . ' (' . $this->baseUrl . ')';
        $lines[] = 'Application key : ' . self::mask($this->applicationKey);

        // État du jeton.
        try {
            $cred = $this->call('GET', '/auth/currentCredential');
            if (is_array($cred)) {
                $status = isset($cred['status']) ? (string) $cred['status'] : '?';
                if ($status !== 'validated') {
                    throw new acmeException('Jeton OVH dans l\'état « ' . $status . ' » : il doit être validé '
                        . '(ouvrez le lien de validation reçu à la création, ou recréez un jeton).');
                }
                $exp = isset($cred['expiration']) && $cred['expiration'] ? (string) $cred['expiration'] : null;
                $lines[] = 'Jeton : validé, ' . ($exp === null ? 'sans expiration' : 'expire le ' . $exp);
                if (isset($cred['rules']) && is_array($cred['rules'])) {
                    $rules = array();
                    foreach ($cred['rules'] as $rule) {
                        if (isset($rule['method'], $rule['path'])) {
                            $rules[] = $rule['method'] . ' ' . $rule['path'];
                        }
                    }
                    $lines[] = 'Droits : ' . (count($rules) ? implode(', ', $rules) : 'aucun');
                }
            }
        } catch (acmeException $e) {
            if ($e->getCode() == 403 && stripos($e->getMessage(), 'not been granted') !== false) {
                $lines[] = "Jeton : état non consultable (droit GET /auth/currentCredential absent), on continue";
            } else {
                throw $e;
            }
        }

        // Zones accessibles.
        $zones = $this->listZones();
        if ($zones === null) {
            $lines[] = 'Zones : liste non consultable (droit GET /domain/zone absent) ; '
                . 'la zone sera trouvée en sondant GET /domain/zone/<domaine>.';
        } elseif (count($zones) == 0) {
            throw new acmeException("Aucune zone DNS sur ce compte OVH. Vérifiez le point d'accès (ovh-eu, ovh-ca…) "
                . 'et que le domaine utilise bien les serveurs DNS d\'OVHcloud.');
        } else {
            $lines[] = 'Zones accessibles (' . count($zones) . ') : ' . implode(', ', $zones);
        }
        return implode("\n", $lines);
    }

    public function addTxt(string $fqdn, string $value): void {
        $this->requireCredentials();
        $loc = $this->locate($fqdn);
        $body = array(
            'fieldType' => 'TXT',
            'subDomain' => $loc['sub'],
            'target' => $value,
            'ttl' => self::TTL,
        );
        $record = $this->call('POST', '/domain/zone/' . rawurlencode($loc['zone']) . '/record', $body);
        $id = is_array($record) && isset($record['id']) ? $record['id'] : null;
        $this->created[] = array('zone' => $loc['zone'], 'sub' => $loc['sub'], 'value' => $value, 'id' => $id);
        $this->touched[$loc['zone']] = true;
        $this->log('info', 'OVH : TXT ajouté dans la zone ' . $loc['zone'] . ' (sous-domaine « ' . $loc['sub']
            . ' »' . ($id !== null ? ', id ' . $id : '') . ')');
    }

    public function removeTxt(string $fqdn, string $value): void {
        $this->requireCredentials();
        $loc = $this->locate($fqdn);
        $zonePath = '/domain/zone/' . rawurlencode($loc['zone']);

        // Identifiants retenus à la création.
        $ids = array();
        foreach ($this->created as $i => $c) {
            if ($c['zone'] === $loc['zone'] && $c['sub'] === $loc['sub'] && $c['value'] === $value) {
                if ($c['id'] !== null) {
                    $ids[] = $c['id'];
                }
                unset($this->created[$i]);
            }
        }

        // À défaut, recherche des enregistrements de même nom et de même valeur
        // (dans la liste déjà lue par listTxt(), sinon auprès de l'API).
        if (count($ids) == 0) {
            $key = $loc['zone'] . '|' . $loc['sub'];
            $records = isset($this->listed[$key]) ? $this->listed[$key] : $this->findTxt($loc);
            foreach ($records as $id => $target) {
                if (self::sameTarget($target, $value)) {
                    $ids[] = $id;
                    unset($this->listed[$key][$id]);
                }
            }
        }

        if (count($ids) == 0) {
            $this->log('debug', 'OVH : aucun TXT à retirer pour ' . $fqdn);
            return;
        }
        foreach ($ids as $id) {
            try {
                $this->call('DELETE', $zonePath . '/record/' . rawurlencode((string) $id));
                $this->log('info', 'OVH : TXT retiré de la zone ' . $loc['zone'] . ' (id ' . $id . ')');
            } catch (acmeException $e) {
                if ($e->getCode() != 404) {
                    throw $e;
                }
                $this->log('debug', 'OVH : TXT id ' . $id . ' déjà absent');
            }
        }
        $this->touched[$loc['zone']] = true;
    }

    /*
     * Méthode facultative (voir acmeDnsProvider) : valeurs des TXT présents
     * sur ce nom, sans guillemets.
     */
    public function listTxt(string $fqdn): array {
        $this->requireCredentials();
        $loc = $this->locate($fqdn);
        $records = $this->findTxt($loc);
        $this->listed[$loc['zone'] . '|' . $loc['sub']] = $records;
        $values = array();
        foreach ($records as $target) {
            $values[] = self::unquote($target);
        }
        return $values;
    }

    /*
     * Méthode facultative (voir acmeDnsProvider) : suffixes des serveurs DNS
     * d'OVHcloud (dnsXX.ovh.net / nsXX.ovh.net, ovh.ca, anycast.me…).
     */
    public function expectedNameServers(): array {
        return array('ovh.net', 'ovh.ca', 'ovh.us', 'anycast.me');
    }

    /* TXT d'un sous-domaine : [id => cible brute]. */
    protected function findTxt(array $loc): array {
        $zonePath = '/domain/zone/' . rawurlencode($loc['zone']);
        $found = $this->call('GET', $zonePath . '/record?' . http_build_query(
            array('fieldType' => 'TXT', 'subDomain' => $loc['sub']), '', '&', PHP_QUERY_RFC3986));
        $records = array();
        if (is_array($found)) {
            foreach ($found as $id) {
                $rec = $this->call('GET', $zonePath . '/record/' . rawurlencode((string) $id));
                if (is_array($rec) && isset($rec['target'])) {
                    $records[$id] = (string) $rec['target'];
                }
            }
        }
        return $records;
    }

    public function commit(): void {
        foreach (array_keys($this->touched) as $zone) {
            $this->call('POST', '/domain/zone/' . rawurlencode($zone) . '/refresh');
            $this->log('info', 'OVH : zone ' . $zone . ' republiée');
            unset($this->touched[$zone]);
        }
    }

    /*
     * Zone OVH et sous-domaine relatif pour un nom complet : la zone est le
     * plus long suffixe présent sur le compte.
     * Renvoie ['zone' => 'example.org', 'sub' => '_acme-challenge.jeedom'].
     */
    public function locate(string $fqdn): array {
        $fqdn = strtolower(rtrim(trim($fqdn), '.'));
        if (isset($this->zoneCache[$fqdn])) {
            return $this->zoneCache[$fqdn];
        }
        $zone = null;
        $zones = $this->listZones();
        if ($zones !== null) {
            foreach ($zones as $z) {
                $z = strtolower($z);
                if (($fqdn === $z || substr($fqdn, -strlen($z) - 1) === '.' . $z)
                    && ($zone === null || strlen($z) > strlen($zone))) {
                    $zone = $z;
                }
            }
        } else {
            // Liste non autorisée : on sonde les suffixes, du plus long au plus court.
            $labels = explode('.', $fqdn);
            for ($i = 0; $i < count($labels) - 1; $i++) {
                $candidate = implode('.', array_slice($labels, $i));
                try {
                    $this->call('GET', '/domain/zone/' . rawurlencode($candidate));
                    $zone = $candidate;
                    break;
                } catch (acmeException $e) {
                    if ($e->getCode() != 404 && $e->getCode() != 403) {
                        throw $e;
                    }
                }
            }
        }
        if ($zone === null) {
            throw new acmeException('Aucune zone DNS OVH ne correspond à ' . $fqdn
                . ". Le domaine doit être géré par les serveurs DNS d'OVHcloud sur ce compte"
                . " (vérifiez aussi le point d'accès choisi).");
        }
        $sub = $fqdn === $zone ? '' : substr($fqdn, 0, -strlen($zone) - 1);
        return $this->zoneCache[$fqdn] = array('zone' => $zone, 'sub' => $sub);
    }

    /* Zones du compte, ou null si le jeton n'a pas le droit de les lister. */
    protected function listZones(): ?array {
        if ($this->zones !== null) {
            return $this->zones;
        }
        try {
            $zones = $this->call('GET', '/domain/zone');
        } catch (acmeException $e) {
            if ($e->getCode() == 403 && stripos($e->getMessage(), 'not been granted') !== false) {
                return null;
            }
            throw $e;
        }
        $this->zones = is_array($zones) ? array_values(array_map('strval', $zones)) : array();
        return $this->zones;
    }

    /* OVH peut renvoyer la cible entourée de guillemets. */
    protected static function sameTarget(string $target, string $value): bool {
        return self::unquote($target) === $value;
    }

    protected static function unquote(string $target): string {
        $t = trim($target);
        if (strlen($t) >= 2 && $t[0] === '"' && substr($t, -1) === '"') {
            $t = acmeDnsCheck::parseTxtPresentation($t);
        }
        return $t;
    }

    /* Appel signé à l'API. Renvoie le JSON décodé (null pour un corps vide). */
    protected function call(string $method, string $path, ?array $body = null, bool $signed = true) {
        $url = $this->baseUrl . $path;
        $bodyStr = $body === null ? '' : json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $headers = array('Accept: application/json');
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }
        if ($signed) {
            $timestamp = time() + $this->getTimeDelta();
            $headers[] = 'X-Ovh-Application: ' . $this->applicationKey;
            $headers[] = 'X-Ovh-Consumer: ' . $this->consumerKey;
            $headers[] = 'X-Ovh-Timestamp: ' . $timestamp;
            $headers[] = 'X-Ovh-Signature: ' . self::signature($this->applicationSecret, $this->consumerKey,
                $method, $url, $bodyStr, $timestamp);
        }
        $this->log('debug', 'OVH ' . $method . ' ' . $path);
        $response = $this->httpRequest($method, $url, $headers, $bodyStr);
        if ($response['error'] !== '' || $response['code'] == 0) {
            throw new acmeException("Impossible de joindre l'API OVH (" . $this->baseUrl . ') : '
                . ($response['error'] !== '' ? $response['error'] : 'pas de réponse'));
        }
        $code = (int) $response['code'];
        $decoded = $response['body'] === '' ? null : json_decode($response['body'], true);
        if ($code >= 200 && $code < 300) {
            return $decoded;
        }
        $message = is_array($decoded) && isset($decoded['message']) ? (string) $decoded['message'] : 'HTTP ' . $code;
        $errorCode = is_array($decoded) && isset($decoded['errorCode']) ? (string) $decoded['errorCode'] : '';
        throw new acmeException('OVH ' . $method . ' ' . strtok($path, '?') . ' : ' . $message
            . self::advice($code, $message, $errorCode), is_array($decoded) ? $decoded : array(), $code);
    }

    /* Conseil en français pour les erreurs OVH courantes. */
    public static function advice(int $code, string $message, string $errorCode = ''): string {
        $m = strtolower($message);
        if ($errorCode === 'INVALID_SIGNATURE' || strpos($m, 'invalid signature') !== false) {
            return " — l'application secret ne correspond pas à l'application key (ou la consumer key est erronée) : "
                . 'recopiez les trois valeurs issues de la même création de jeton.';
        }
        if ($errorCode === 'NOT_GRANTED_CALL' || strpos($m, 'not been granted') !== false) {
            return ' — le jeton (consumer key) n\'a pas le droit de faire cet appel : '
                . 'recréez un jeton avec GET, POST et DELETE sur /domain/zone/*.';
        }
        if ($errorCode === 'NOT_CREDENTIAL' || $errorCode === 'INVALID_CREDENTIAL'
            || strpos($m, 'invalid credential') !== false || strpos($m, 'this credential') !== false) {
            return ' — consumer key inconnue, expirée, révoquée ou jamais validée : recréez un jeton '
                . '(validité illimitée conseillée).';
        }
        if ($errorCode === 'INVALID_KEY' || strpos($m, 'invalid application key') !== false
            || strpos($m, 'application key is invalid') !== false) {
            return " — application key inconnue sur ce point d'accès : vérifiez la clé et le point d'accès "
                . '(une clé créée sur ovh-eu ne marche pas sur ovh-ca).';
        }
        if ($errorCode === 'QUERY_TIME_OUT' || strpos($m, 'out of time') !== false || strpos($m, 'timestamp') !== false) {
            return " — l'horloge de la machine est trop décalée : vérifiez la synchronisation NTP.";
        }
        if ($code == 404) {
            return ' — zone ou enregistrement introuvable sur ce compte OVH.';
        }
        if ($code == 429) {
            return ' — trop de requêtes, réessayez dans quelques minutes.';
        }
        if ($code >= 500) {
            return ' — erreur côté OVH, réessayez plus tard.';
        }
        return '';
    }

    /* Décalage d'horloge avec OVH, lu une fois via GET /auth/time (non signé). */
    protected function getTimeDelta(): int {
        if ($this->timeDelta === null) {
            $serverTime = $this->call('GET', '/auth/time', null, false);
            if (!is_numeric($serverTime)) {
                throw new acmeException("Réponse inattendue de l'API OVH pour /auth/time");
            }
            $this->timeDelta = (int) $serverTime - time();
            if (abs($this->timeDelta) > 30) {
                $this->log('warning', 'Horloge locale décalée de ' . $this->timeDelta . ' s par rapport à OVH (corrigé)');
            }
        }
        return $this->timeDelta;
    }

    /*
     * Transport HTTP, surchargeable (ou remplaçable par setTransport()).
     * Renvoie ['code' => int, 'body' => string, 'error' => string].
     */
    protected function httpRequest(string $method, string $url, array $headers, string $body): array {
        if ($this->transport !== null) {
            $r = call_user_func($this->transport, $method, $url, $headers, $body);
            return array(
                'code' => isset($r['code']) ? (int) $r['code'] : 0,
                'body' => isset($r['body']) ? (string) $r['body'] : '',
                'error' => isset($r['error']) ? (string) $r['error'] : '',
            );
        }
        if (!function_exists('curl_init')) {
            return array('code' => 0, 'body' => '', 'error' => 'extension curl absente');
        }
        $ch = curl_init($url);
        $opts = array(
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => 'jeedom-acme',
        );
        if ($method !== 'GET' && $method !== 'DELETE') {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $opts);
        $resp = curl_exec($ch);
        $result = array(
            'code' => (int) curl_getinfo($ch, CURLINFO_HTTP_CODE),
            'body' => is_string($resp) ? $resp : '',
            'error' => $resp === false ? curl_error($ch) : '',
        );
        curl_close($ch);
        return $result;
    }

    protected function requireCredentials(): void {
        $missing = array();
        if ($this->applicationKey === '') {
            $missing[] = 'application key';
        }
        if ($this->applicationSecret === '') {
            $missing[] = 'application secret';
        }
        if ($this->consumerKey === '') {
            $missing[] = 'consumer key';
        }
        if (count($missing)) {
            throw new acmeException('Identifiants OVH incomplets : ' . implode(', ', $missing) . ' manquant(s).');
        }
    }

    /* Masque un secret pour les journaux : « abcd… ». */
    public static function mask(string $secret): string {
        return $secret === '' ? '(vide)' : substr($secret, 0, 4) . '…';
    }

    protected function log(string $level, string $message): void {
        if ($this->logger === null) {
            return;
        }
        try {
            call_user_func($this->logger, $level, $message);
        } catch (Throwable $e) {
            // Un journal défaillant ne doit jamais interrompre l'opération.
        }
    }
}

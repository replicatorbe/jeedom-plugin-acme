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
 * Validation DNS-01 : interface des fournisseurs DNS, registre des
 * fournisseurs, et vérification de la propagation d'un enregistrement TXT
 * auprès des serveurs faisant autorité.
 *
 * Aucune dépendance au cœur de Jeedom : seules les extensions PHP standard
 * (et curl pour le repli DoH) sont utilisées. Les erreurs lèvent
 * acmeException, définie dans acmeClient.class.php.
 */

/*
 * Fournisseur DNS capable de poser et retirer des enregistrements TXT.
 *
 * Méthodes facultatives (hors interface, détectées par method_exists()) :
 *  - listTxt(string $fqdn): array — valeurs TXT présentes sur ce nom ; sert
 *    seulement au journal (TXT d'un autre outil laissés en place) : aucun TXT
 *    n'est retiré d'après sa forme ;
 *  - recordId(string $fqdn, string $value): ?string — identifiant, chez le
 *    fournisseur, du TXT tout juste posé par addTxt() ; retenu dans le
 *    fichier d'état du solveur ;
 *  - removeTxtById(string $fqdn, string $value, string $id): bool — retire le
 *    TXT d'identifiant connu (reste d'une tâche interrompue) ; renvoie false
 *    si le fournisseur ne le connaît plus ;
 *  - expectedNameServers(): array — suffixes des serveurs DNS du fournisseur
 *    (ex. 'ovh.net') ; sert à avertir quand la zone est servie ailleurs.
 */
interface acmeDnsProvider {

    public function __construct(array $config, ?callable $logger = null);

    /* Nom lisible du fournisseur, ex. « OVHcloud ». */
    public static function getLabel(): string;

    /* Champs affichés par l'interface : clé => ['label' => ..., 'type' =>
     * 'text'|'password'|'select', 'options' => [valeur => libellé] (select),
     * 'default' => ..., 'help' => ...] */
    public static function getFields(): array;

    /* Vérifie les accès, renvoie un résumé lisible, lève sinon. */
    public function test(): string;

    public function addTxt(string $fqdn, string $value): void;

    public function removeTxt(string $fqdn, string $value): void;

    /* Publie les modifications (ex. OVH : POST /domain/zone/{zone}/refresh). */
    public function commit(): void;
}

/*
 * Registre des fournisseurs DNS connus.
 */
class acmeDns {

    /* Identifiant => nom de la classe. Le fichier de la classe porte son nom :
     * <classe>.class.php, dans ce même dossier. */
    public static function providers(): array {
        return array('ovh' => 'acmeDnsOvh');
    }

    public static function create(string $id, array $config, ?callable $logger = null): acmeDnsProvider {
        $providers = self::providers();
        if (!isset($providers[$id])) {
            throw new acmeException('Fournisseur DNS inconnu : ' . $id
                . ' (connus : ' . implode(', ', array_keys($providers)) . ')');
        }
        $class = $providers[$id];
        if (!class_exists($class, false)) {
            $file = __DIR__ . '/' . $class . '.class.php';
            if (is_file($file)) {
                require_once $file;
            }
        }
        if (!class_exists($class, false)) {
            throw new acmeException('Classe du fournisseur DNS introuvable : ' . $class);
        }
        $provider = new $class($config, $logger);
        if (!($provider instanceof acmeDnsProvider)) {
            throw new acmeException('La classe ' . $class . " n'implémente pas acmeDnsProvider");
        }
        return $provider;
    }
}

/*
 * Vérification de la visibilité d'un enregistrement TXT.
 *
 * Principe : on interroge directement les serveurs faisant autorité pour la
 * zone (requête DNS brute, sans récursion), en IPv4 et en IPv6, ce qui évite
 * les caches des résolveurs. Si aucun serveur ne répond (UDP et TCP 53
 * sortants bloqués), on se replie sur DNS-over-HTTPS (Cloudflare, puis
 * Google), qui passe par un résolveur récursif : une réponse négative y est
 * mise en cache (jusqu'au minimum du SOA, 86400 s chez OVH), si bien qu'un
 * « pas vu » en DoH ne prouve rien et est rendu comme « inconnu ».
 */
class acmeDnsCheck {

    const TYPE_A = 1;
    const TYPE_NS = 2;
    const TYPE_CNAME = 5;
    const TYPE_SOA = 6;
    const TYPE_TXT = 16;
    const TYPE_OPT = 41;

    const MAX_CNAME_HOPS = 8;

    /* États renvoyés par txtStatus(). */
    const VISIBLE = 'visible';
    const MISSING = 'missing';
    const UNKNOWN = 'unknown';

    /* Mode de vérification : 'auto' (direct puis DoH), 'direct' (serveurs
     * d'autorité seulement) ou 'doh' (DoH seulement, utile pour les tests). */
    public static $mode = 'auto';

    /* Délai d'attente d'une réponse d'un serveur, en secondes. */
    public static $timeout = 2;

    /* Points d'accès DoH (format JSON), essayés dans l'ordre. */
    public static $dohEndpoints = array(
        'https://cloudflare-dns.com/dns-query',
        'https://dns.google/resolve',
    );

    /* Crochets de test (null en service) :
     *  - $queryHook  : function (string $ip, string $name, int $type): ?array,
     *    remplace queryServer() (même format de retour) ;
     *  - $dohHook    : function (string $endpoint, string $name): ?array,
     *    remplace dohTxt() (valeurs TXT, ou null si le point d'accès échoue) ;
     *  - $lookupHook : function (string $name, int $type): array, remplace
     *    dns_get_record() (et gethostbynamel()) ; $type est une constante DNS_*. */
    public static $queryHook = null;
    public static $dohHook = null;
    public static $lookupHook = null;

    /* Vrai quand, dans ce processus, aucun serveur d'autorité n'a pu être
     * joint : les appels suivants passent directement par DoH au lieu
     * d'attendre à nouveau l'expiration des délais. */
    protected static $directBlocked = false;

    /* Familles d'adresses (4 ou 6) sans aucune réponse alors que l'autre
     * répond : ignorées ensuite pour ne pas attendre leurs délais. */
    protected static $brokenFamily = array();

    /* Cache zone => liste d'adresses IP des serveurs d'autorité. */
    protected static $nsCache = array();

    /* Cache zone => noms des serveurs d'autorité, et adresse => nom. */
    protected static $nsHosts = array();
    protected static $ipHosts = array();

    /*
     * Vrai quand TOUS les serveurs faisant autorité joignables renvoient la
     * valeur (au moins un doit répondre), ou quand le repli DoH la voit. Un
     * CNAME sur le nom (délégation de la validation) est suivi.
     */
    public static function txtVisible(string $fqdn, string $value, ?callable $logger = null): bool {
        $status = self::txtStatus($fqdn, $value, $logger);
        return $status['state'] === self::VISIBLE;
    }

    /*
     * État détaillé de la visibilité d'un TXT :
     *   ['state'    => 'visible' | 'missing' | 'unknown',
     *    'method'   => 'direct' | 'doh' | 'none',
     *    'zone'     => ?string (zone interrogée),
     *    'name'     => string (nom final, après CNAME),
     *    'servers'  => string[] (« serveur (adresse) : ce qu'il a renvoyé »),
     *    'deferred' => bool (DoH nécessaire mais pas encore autorisé),
     *    'details'  => string (résumé lisible)]
     * 'missing' n'est rendu que sur la foi des serveurs d'autorité eux-mêmes.
     * 'unknown' : impossible à vérifier (aucun serveur d'autorité joignable
     * et DoH en échec), ou DoH seul qui ne voit pas encore la valeur (cache
     * négatif possible). $allowDoh = false : pas d'appel DoH, état
     * 'unknown' avec 'deferred' = true si DoH était nécessaire.
     */
    public static function txtStatus(string $fqdn, string $value, ?callable $logger = null, bool $allowDoh = true): array {
        $name = self::normalizeName($fqdn);
        if ($name === '') {
            throw new acmeException('Nom DNS vide');
        }
        $mode = self::$mode;
        if ($mode === 'doh') {
            return self::dohStatus($name, $value, $logger, $allowDoh, 'mode DNS-over-HTTPS', array());
        }
        if ($mode === 'auto' && self::$directBlocked) {
            return self::dohStatus($name, $value, $logger, $allowDoh,
                'serveurs faisant autorité injoignables (port 53 sortant bloqué ?)', array());
        }

        $hops = 0;
        $lines = array();
        while (true) {
            $zone = null;
            $servers = self::authoritativeServers($name, $logger, $zone);
            if (count($servers) == 0) {
                self::log($logger, 'warning', 'Serveurs faisant autorité introuvables pour ' . $name);
                return self::fallbackStatus($name, $value, $logger, $allowDoh,
                    'serveurs faisant autorité introuvables pour ' . $name, $lines);
            }

            $reachable = 0;
            $seen = 0;
            $cname = null;
            $ok = array();
            $failed = array();
            foreach ($servers as $ip) {
                $family = self::family($ip);
                $label = self::serverLabel($ip);
                if (isset(self::$brokenFamily[$family])) {
                    continue;
                }
                $result = self::queryServer($ip, $name, self::TYPE_TXT, $logger);
                if ($result === null) {
                    self::log($logger, 'debug', 'Pas de réponse exploitable de ' . $ip . ' pour ' . $name);
                    $lines[] = $label . ' : pas de réponse';
                    $failed[$family] = true;
                    continue;
                }
                $ok[$family] = true;
                $reachable++;
                if ($result['cname'] !== null) {
                    $cname = $result['cname'];
                    $lines[] = $label . ' : ' . $name . ' est un CNAME vers ' . $cname;
                    continue;
                }
                if (in_array($value, $result['txt'], true)) {
                    $seen++;
                    $lines[] = $label . ' : valeur présente';
                } else {
                    $lines[] = $label . ' : ' . self::describeAnswer($result);
                    self::log($logger, 'debug', 'Valeur pas encore visible sur ' . $ip . ' pour ' . $name);
                }
            }
            self::noteFamilies($ok, $failed, $logger);

            if ($reachable == 0) {
                $why = 'aucun serveur faisant autorité joignable pour ' . $name . ' (port 53 sortant bloqué ?)';
                self::log($logger, 'warning', ucfirst($why) . ($mode === 'auto' ? ' : repli sur DNS-over-HTTPS' : ''));
                if ($mode === 'auto') {
                    self::$directBlocked = true;
                }
                return self::fallbackStatus($name, $value, $logger, $allowDoh, $why, $lines);
            }

            if ($cname !== null) {
                if (++$hops > self::MAX_CNAME_HOPS) {
                    self::log($logger, 'warning', 'Trop de CNAME en chaîne pour ' . $fqdn);
                    return self::status(self::MISSING, 'direct', $zone, $name, $lines,
                        'Trop de CNAME en chaîne pour ' . $fqdn);
                }
                self::log($logger, 'debug', $name . ' est un CNAME vers ' . $cname . ' : on le suit');
                $name = $cname;
                continue;
            }

            $details = 'TXT ' . $name . ' : valeur visible sur ' . $seen . '/' . $reachable
                . " serveur(s) faisant autorité joignable(s) (zone " . $zone . ')';
            self::log($logger, 'debug', $details);
            return self::status($seen == $reachable ? self::VISIBLE : self::MISSING, 'direct', $zone, $name,
                $lines, $details);
        }
    }

    /*
     * Cible finale du CNAME posé sur $fqdn (délégation de la validation), ou
     * null s'il n'y en a pas. Interroge les serveurs faisant autorité, puis le
     * résolveur du système en repli.
     */
    public static function cnameTarget(string $fqdn, ?callable $logger = null): ?string {
        $start = self::normalizeName($fqdn);
        $name = $start;
        for ($hop = 0; ; $hop++) {
            $next = self::cnameOf($name, $logger);
            if ($next === null || $next === $name) {
                break;
            }
            if ($hop >= self::MAX_CNAME_HOPS) {
                throw new acmeException('Trop de CNAME en chaîne pour ' . $fqdn);
            }
            $name = $next;
        }
        return $name === $start ? null : $name;
    }

    /* CNAME direct d'un nom, ou null. */
    protected static function cnameOf(string $name, ?callable $logger): ?string {
        if (self::$mode !== 'doh' && !self::$directBlocked) {
            $servers = self::authoritativeServers($name, $logger);
            foreach ($servers as $ip) {
                $family = self::family($ip);
                if (isset(self::$brokenFamily[$family])) {
                    continue;
                }
                $result = self::queryServer($ip, $name, self::TYPE_CNAME, $logger);
                if ($result !== null) {
                    return $result['cname'];
                }
            }
            if (count($servers) > 0 && self::$mode === 'auto') {
                // Aucun serveur d'autorité joignable : inutile de réessayer plus tard.
                self::$directBlocked = true;
            }
        }
        // Repli : résolveur du système.
        foreach (self::systemLookup($name, DNS_CNAME) as $record) {
            if (isset($record['type'], $record['host'], $record['target']) && $record['type'] === 'CNAME'
                && self::normalizeName($record['host']) === $name) {
                return self::normalizeName($record['target']);
            }
        }
        return null;
    }

    /*
     * Noms des serveurs faisant autorité pour la zone qui contient $name
     * (ex. dns14.ovh.net, ns14.ovh.net) ; $zone reçoit le nom de la zone.
     */
    public static function authoritativeNameServers(string $name, ?callable $logger = null, ?string &$zone = null): array {
        self::authoritativeServers($name, $logger, $zone);
        return $zone !== null && isset(self::$nsHosts[$zone]) ? self::$nsHosts[$zone] : array();
    }

    /*
     * Adresses IP des serveurs faisant autorité pour la zone qui contient
     * $name : on remonte les labels jusqu'à trouver des enregistrements NS.
     * $zone reçoit le nom de la zone trouvée.
     */
    public static function authoritativeServers(string $name, ?callable $logger = null, ?string &$zone = null): array {
        $labels = explode('.', self::normalizeName($name));
        $count = count($labels);
        for ($i = 0; $i < $count - 1; $i++) {
            $candidate = implode('.', array_slice($labels, $i));
            if (isset(self::$nsCache[$candidate])) {
                $zone = $candidate;
                return self::$nsCache[$candidate];
            }
            $records = self::systemLookup($candidate, DNS_NS);
            if (count($records) == 0) {
                continue;
            }
            $hosts = array();
            foreach ($records as $record) {
                if (isset($record['type'], $record['host'], $record['target']) && $record['type'] === 'NS'
                    && self::normalizeName($record['host']) === $candidate) {
                    $hosts[] = self::normalizeName($record['target']);
                }
            }
            if (count($hosts) == 0) {
                continue;
            }
            $hosts = array_values(array_unique($hosts));
            $ips = array();
            foreach ($hosts as $host) {
                $found = self::resolveHost($host);
                if (count($found) == 0) {
                    self::log($logger, 'debug', 'Adresse introuvable pour le serveur ' . $host);
                }
                foreach ($found as $ip) {
                    $ips[$ip] = true;
                    self::$ipHosts[$ip] = $host;
                }
            }
            $zone = $candidate;
            $ips = array_keys($ips);
            self::log($logger, 'debug', 'Zone ' . $candidate . ' : serveurs ' . implode(', ', $hosts)
                . ' (' . implode(', ', $ips) . ')');
            self::$nsCache[$candidate] = $ips;
            self::$nsHosts[$candidate] = $hosts;
            return $ips;
        }
        return array();
    }

    /* Adresses d'un serveur : une IPv4 et une IPv6 (si elles existent), pour
     * fonctionner aussi sur une machine sans IPv4 (ou sans IPv6). */
    protected static function resolveHost(string $host): array {
        $ips = array();
        if (self::$lookupHook === null) {
            $v4 = @gethostbynamel($host);
            if (is_array($v4) && count($v4) > 0) {
                $ips[] = $v4[0];
            }
        } else {
            foreach (self::systemLookup($host, DNS_A) as $record) {
                if (isset($record['ip'])) {
                    $ips[] = $record['ip'];
                    break;
                }
            }
        }
        foreach (self::systemLookup($host, DNS_AAAA) as $record) {
            if (isset($record['ipv6'])) {
                $ips[] = $record['ipv6'];
                break;
            }
        }
        return $ips;
    }

    /* dns_get_record() sans avertissement, remplaçable (tests). */
    protected static function systemLookup(string $name, int $type): array {
        if (self::$lookupHook !== null) {
            $records = call_user_func(self::$lookupHook, $name, $type);
        } else {
            $records = @dns_get_record($name, $type);
        }
        return is_array($records) ? $records : array();
    }

    protected static function family(string $ip): int {
        return strpos($ip, ':') !== false ? 6 : 4;
    }

    /* « dns14.ovh.net (213.251.188.143) », ou l'adresse seule. */
    protected static function serverLabel(string $ip): string {
        return isset(self::$ipHosts[$ip]) ? self::$ipHosts[$ip] . ' (' . $ip . ')' : $ip;
    }

    /* Retient une famille d'adresses muette quand l'autre répond. */
    protected static function noteFamilies(array $ok, array $failed, ?callable $logger): void {
        if (count($ok) == 0) {
            return;
        }
        foreach (array_keys($failed) as $family) {
            if (!isset($ok[$family]) && !isset(self::$brokenFamily[$family])) {
                self::$brokenFamily[$family] = true;
                self::log($logger, 'debug', 'Aucune réponse en IPv' . $family . ' : cette famille est ignorée ensuite');
            }
        }
    }

    /* Ce qu'un serveur a renvoyé, quand la valeur attendue n'y est pas. */
    protected static function describeAnswer(array $result): string {
        if ($result['rcode'] == 3) {
            return 'nom inexistant (NXDOMAIN)';
        }
        if (count($result['txt']) == 0) {
            return 'aucun TXT sur ce nom';
        }
        $shown = array();
        foreach (array_slice($result['txt'], 0, 3) as $txt) {
            $shown[] = '« ' . (strlen($txt) > 60 ? substr($txt, 0, 60) . '…' : $txt) . ' »';
        }
        return 'valeur absente (TXT présents : ' . implode(', ', $shown)
            . (count($result['txt']) > 3 ? ', …' : '') . ')';
    }

    protected static function status(string $state, string $method, ?string $zone, string $name, array $servers,
                                     string $details, bool $deferred = false): array {
        return array(
            'state' => $state,
            'method' => $method,
            'zone' => $zone,
            'name' => $name,
            'servers' => $servers,
            'deferred' => $deferred,
            'details' => $details,
        );
    }

    /* Serveurs d'autorité inutilisables : DoH (mode auto), sinon inconnu. */
    protected static function fallbackStatus(string $name, string $value, ?callable $logger, bool $allowDoh,
                                             string $why, array $lines): array {
        if (self::$mode === 'direct') {
            return self::status(self::UNKNOWN, 'none', null, $name, $lines, ucfirst($why) . ' : vérification impossible.');
        }
        return self::dohStatus($name, $value, $logger, $allowDoh, $why, $lines);
    }

    /*
     * Interroge un serveur (sans récursion). Renvoie null si le serveur ne
     * répond pas ou refuse (serveur non autoritaire), sinon :
     *   ['rcode' => int, 'txt' => string[], 'cname' => ?string]
     * 'cname' est la cible finale d'une chaîne CNAME dont le TXT n'est pas
     * dans la réponse (il faut alors interroger la zone de la cible).
     */
    public static function queryServer(string $ip, string $name, int $type = self::TYPE_TXT, ?callable $logger = null): ?array {
        if (self::$queryHook !== null) {
            $r = call_user_func(self::$queryHook, $ip, self::normalizeName($name), $type);
            return is_array($r) ? array_merge(array('rcode' => 0, 'txt' => array(), 'cname' => null), $r) : null;
        }
        $edns = true;
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $id = random_int(0, 0xFFFF);
            $packet = self::buildQuery($id, $name, $type, $edns);
            $raw = self::sendUdp($ip, $packet, $id);
            $viaTcp = false;
            if ($raw === null) {
                // Pas de réponse en UDP : on tente TCP une fois avant d'abandonner.
                $raw = self::sendTcp($ip, $packet, $id);
                $viaTcp = true;
                if ($raw === null) {
                    return null;
                }
            }
            try {
                $response = self::parseResponse($raw, $name, $type);
            } catch (Exception $e) {
                self::log($logger, 'debug', 'Réponse DNS illisible de ' . $ip . ' : ' . $e->getMessage());
                return null;
            }
            if ($response['tc'] && !$viaTcp) {
                // Réponse tronquée : on recommence en TCP.
                $raw = self::sendTcp($ip, $packet, $id);
                if ($raw === null) {
                    return null;
                }
                try {
                    $response = self::parseResponse($raw, $name, $type);
                } catch (Exception $e) {
                    return null;
                }
            }
            if ($response['rcode'] == 1 && $edns) {
                // FORMERR : serveur ancien qui ne comprend pas EDNS0.
                $edns = false;
                continue;
            }
            if ($response['rcode'] != 0 && $response['rcode'] != 3) {
                // SERVFAIL, REFUSED… : réponse inexploitable.
                return null;
            }
            return array(
                'rcode' => $response['rcode'],
                'txt' => $response['txt'],
                'cname' => $response['cname'],
            );
        }
        return null;
    }

    /* Construit une requête DNS (RD = 0), avec un enregistrement OPT EDNS0
     * annonçant 1232 octets pour limiter les réponses tronquées. */
    public static function buildQuery(int $id, string $name, int $type, bool $edns = true): string {
        $packet = pack('nnnnnn', $id, 0x0000, 1, 0, 0, $edns ? 1 : 0);
        $packet .= self::encodeName($name);
        $packet .= pack('nn', $type, 1);
        if ($edns) {
            $packet .= "\x00" . pack('nnNn', self::TYPE_OPT, 1232, 0, 0);
        }
        return $packet;
    }

    public static function encodeName(string $name): string {
        $name = self::normalizeName($name);
        if ($name === '') {
            return "\x00";
        }
        if (strlen($name) > 253) {
            throw new acmeException('Nom DNS trop long : ' . $name);
        }
        $out = '';
        foreach (explode('.', $name) as $label) {
            $len = strlen($label);
            if ($len == 0 || $len > 63) {
                throw new acmeException('Label DNS invalide dans ' . $name);
            }
            $out .= chr($len) . $label;
        }
        return $out . "\x00";
    }

    /*
     * Analyse une réponse DNS. Renvoie :
     *   ['id', 'tc' => bool, 'aa' => bool, 'rcode' => int, 'txt' => string[], 'cname' => ?string]
     * Les CNAME du nom demandé sont suivis dans la réponse ; si la cible
     * n'a pas de TXT dans la réponse, 'cname' contient cette cible.
     */
    public static function parseResponse(string $raw, string $qname, int $qtype = self::TYPE_TXT): array {
        $len = strlen($raw);
        if ($len < 12) {
            throw new acmeException('réponse trop courte');
        }
        $h = unpack('nid/nflags/nqd/nan/nns/nar', substr($raw, 0, 12));
        if (($h['flags'] & 0x8000) == 0) {
            throw new acmeException("ce n'est pas une réponse");
        }
        $result = array(
            'id' => $h['id'],
            'tc' => ($h['flags'] & 0x0200) != 0,
            'aa' => ($h['flags'] & 0x0400) != 0,
            'rcode' => $h['flags'] & 0x000F,
            'txt' => array(),
            'cname' => null,
        );
        $off = 12;
        for ($i = 0; $i < $h['qd']; $i++) {
            self::readName($raw, $off);
            $off += 4;
        }
        $cnames = array();
        $txts = array();
        for ($i = 0; $i < $h['an']; $i++) {
            $owner = self::readName($raw, $off);
            if ($off + 10 > $len) {
                throw new acmeException('enregistrement tronqué');
            }
            $rr = unpack('ntype/nclass/Nttl/nrdlen', substr($raw, $off, 10));
            $off += 10;
            $rdStart = $off;
            if ($rdStart + $rr['rdlen'] > $len) {
                throw new acmeException('données tronquées');
            }
            if ($rr['type'] == self::TYPE_CNAME) {
                $p = $rdStart;
                $cnames[$owner] = self::readName($raw, $p);
            } elseif ($rr['type'] == $qtype && $qtype == self::TYPE_TXT) {
                $txts[$owner][] = self::parseTxtRdata(substr($raw, $rdStart, $rr['rdlen']));
            }
            $off = $rdStart + $rr['rdlen'];
        }
        // Suit la chaîne de CNAME présente dans la réponse.
        $current = self::normalizeName($qname);
        $guard = 0;
        while (isset($cnames[$current]) && $guard++ < self::MAX_CNAME_HOPS) {
            $current = $cnames[$current];
        }
        if (isset($txts[$current])) {
            $result['txt'] = $txts[$current];
        } elseif ($current !== self::normalizeName($qname)) {
            $result['cname'] = $current;
        }
        return $result;
    }

    /* Un TXT est une suite de chaînes <longueur><octets> à concaténer. */
    public static function parseTxtRdata(string $rdata): string {
        $out = '';
        $pos = 0;
        $len = strlen($rdata);
        while ($pos < $len) {
            $l = ord($rdata[$pos]);
            $out .= substr($rdata, $pos + 1, $l);
            $pos += 1 + $l;
        }
        return $out;
    }

    /* Lit un nom (avec compression) ; $off est placé après le nom. */
    public static function readName(string $raw, int &$off): string {
        $len = strlen($raw);
        $labels = array();
        $pos = $off;
        $jumped = false;
        $guard = 0;
        while (true) {
            if ($pos >= $len) {
                throw new acmeException('nom tronqué');
            }
            $l = ord($raw[$pos]);
            if ($l == 0) {
                $pos++;
                break;
            }
            if (($l & 0xC0) == 0xC0) {
                if ($pos + 1 >= $len) {
                    throw new acmeException('pointeur tronqué');
                }
                $ptr = (($l & 0x3F) << 8) | ord($raw[$pos + 1]);
                if (!$jumped) {
                    $off = $pos + 2;
                }
                $jumped = true;
                if (++$guard > 64 || $ptr >= $len) {
                    throw new acmeException('boucle de compression');
                }
                $pos = $ptr;
                continue;
            }
            if (($l & 0xC0) != 0) {
                throw new acmeException('type de label inconnu');
            }
            if ($pos + 1 + $l > $len) {
                throw new acmeException('label tronqué');
            }
            $labels[] = substr($raw, $pos + 1, $l);
            $pos += 1 + $l;
        }
        if (!$jumped) {
            $off = $pos;
        }
        return strtolower(implode('.', $labels));
    }

    protected static function formatAddress(string $ip): string {
        return strpos($ip, ':') !== false ? '[' . $ip . ']' : $ip;
    }

    /* Envoie en UDP ; renvoie la réponse dont l'identifiant correspond, ou
     * null (pas de réponse, 2 essais). */
    protected static function sendUdp(string $ip, string $packet, int $id): ?string {
        for ($try = 0; $try < 2; $try++) {
            $errno = 0;
            $errstr = '';
            $sock = @stream_socket_client('udp://' . self::formatAddress($ip) . ':53', $errno, $errstr, self::$timeout);
            if ($sock === false) {
                return null;
            }
            stream_set_timeout($sock, (int) self::$timeout);
            if (@fwrite($sock, $packet) === false) {
                fclose($sock);
                return null;
            }
            $deadline = microtime(true) + self::$timeout;
            while (microtime(true) < $deadline) {
                $data = @fread($sock, 65535);
                if ($data === false || $data === '') {
                    $meta = stream_get_meta_data($sock);
                    if (!empty($meta['timed_out'])) {
                        break;
                    }
                    // Erreur ICMP (port fermé) : inutile d'insister.
                    fclose($sock);
                    return null;
                }
                if (strlen($data) >= 2 && unpack('n', substr($data, 0, 2))[1] == $id) {
                    fclose($sock);
                    return $data;
                }
            }
            fclose($sock);
        }
        return null;
    }

    /* Envoie en TCP (préfixe de longueur sur 2 octets). */
    protected static function sendTcp(string $ip, string $packet, int $id): ?string {
        $errno = 0;
        $errstr = '';
        $sock = @stream_socket_client('tcp://' . self::formatAddress($ip) . ':53', $errno, $errstr, self::$timeout + 1);
        if ($sock === false) {
            return null;
        }
        stream_set_timeout($sock, (int) self::$timeout + 1);
        if (@fwrite($sock, pack('n', strlen($packet)) . $packet) === false) {
            fclose($sock);
            return null;
        }
        $head = self::readExactly($sock, 2);
        if ($head === null) {
            fclose($sock);
            return null;
        }
        $size = unpack('n', $head)[1];
        $data = self::readExactly($sock, $size);
        fclose($sock);
        if ($data === null || strlen($data) < 2 || unpack('n', substr($data, 0, 2))[1] != $id) {
            return null;
        }
        return $data;
    }

    protected static function readExactly($sock, int $size): ?string {
        $data = '';
        while (strlen($data) < $size) {
            $chunk = @fread($sock, $size - strlen($data));
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($sock);
                if (!empty($meta['timed_out']) || feof($sock)) {
                    return null;
                }
                continue;
            }
            $data .= $chunk;
        }
        return $data;
    }

    /*
     * Repli DNS-over-HTTPS (format JSON). Le premier point d'accès qui répond
     * fait foi. Le résolveur suit lui-même les CNAME. Vrai seulement si la
     * valeur est vue.
     */
    public static function txtVisibleDoh(string $fqdn, string $value, ?callable $logger = null): bool {
        $status = self::dohStatus(self::normalizeName($fqdn), $value, $logger, true, 'DNS-over-HTTPS', array());
        return $status['state'] === self::VISIBLE;
    }

    /*
     * État via DoH : 'visible', ou 'unknown' (pas encore vu — le résolveur
     * peut servir une réponse négative en cache —, aucun point d'accès
     * joignable, ou DoH pas encore autorisé : 'deferred').
     */
    protected static function dohStatus(string $name, string $value, ?callable $logger, bool $allowDoh,
                                        string $why, array $lines): array {
        if (!$allowDoh) {
            return self::status(self::UNKNOWN, 'doh', null, $name, $lines,
                ucfirst($why) . ' ; vérification par DNS-over-HTTPS différée.', true);
        }
        foreach (self::$dohEndpoints as $endpoint) {
            $host = (string) parse_url($endpoint, PHP_URL_HOST);
            $values = self::dohTxt($endpoint, $name, $logger);
            if ($values === null) {
                $lines[] = 'DoH ' . $host . ' : pas de réponse';
                continue;
            }
            $visible = in_array($value, $values, true);
            self::log($logger, 'debug', 'DoH ' . $host . ' : TXT ' . $name
                . ($visible ? ' visible' : ' pas encore visible'));
            if ($visible) {
                $lines[] = 'DoH ' . $host . ' : valeur présente';
                return self::status(self::VISIBLE, 'doh', null, $name, $lines,
                    'TXT ' . $name . ' : valeur visible via DNS-over-HTTPS (' . $host . ')');
            }
            $lines[] = 'DoH ' . $host . ' : valeur pas encore visible (' . count($values) . ' TXT)';
            return self::status(self::UNKNOWN, 'doh', null, $name, $lines,
                ucfirst($why) . ' ; via DNS-over-HTTPS (' . $host . '), valeur pas encore visible, ce qui ne prouve '
                . "rien : le résolveur peut servir une réponse négative mise en cache.");
        }
        self::log($logger, 'warning', 'Aucun serveur DNS-over-HTTPS joignable pour vérifier ' . $name);
        return self::status(self::UNKNOWN, 'none', null, $name, $lines,
            ucfirst($why) . ", et aucun serveur DNS-over-HTTPS joignable : vérification impossible.");
    }

    /* Valeurs TXT renvoyées par un point d'accès DoH, ou null en cas d'échec. */
    public static function dohTxt(string $endpoint, string $name, ?callable $logger = null): ?array {
        if (self::$dohHook !== null) {
            $r = call_user_func(self::$dohHook, $endpoint, $name);
            return is_array($r) ? array_values(array_map('strval', $r)) : null;
        }
        if (!function_exists('curl_init')) {
            return null;
        }
        $url = $endpoint . '?name=' . rawurlencode($name) . '&type=TXT';
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Accept: application/dns-json'),
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_USERAGENT => 'jeedom-acme',
        ));
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        if ($body === false || $code != 200) {
            self::log($logger, 'debug', 'DoH ' . $endpoint . ' en échec : ' . ($error !== '' ? $error : 'HTTP ' . $code));
            return null;
        }
        $json = json_decode((string) $body, true);
        if (!is_array($json) || !isset($json['Status'])) {
            return null;
        }
        if ($json['Status'] != 0 && $json['Status'] != 3) {
            // SERVFAIL ou autre : ce résolveur ne sait pas répondre.
            return null;
        }
        $values = array();
        if (isset($json['Answer']) && is_array($json['Answer'])) {
            foreach ($json['Answer'] as $answer) {
                if (isset($answer['type'], $answer['data']) && (int) $answer['type'] == self::TYPE_TXT) {
                    $values[] = self::parseTxtPresentation((string) $answer['data']);
                }
            }
        }
        return $values;
    }

    /* Convertit un TXT au format texte (« "a" "b" », guillemets et \DDD
     * éventuels) en valeur concaténée. Sans guillemets, renvoyé tel quel. */
    public static function parseTxtPresentation(string $data): string {
        $data = trim($data);
        if ($data === '' || $data[0] !== '"') {
            return $data;
        }
        $out = '';
        $len = strlen($data);
        $in = false;
        for ($i = 0; $i < $len; $i++) {
            $c = $data[$i];
            if (!$in) {
                if ($c === '"') {
                    $in = true;
                }
                continue;
            }
            if ($c === '\\' && $i + 1 < $len) {
                if ($i + 3 < $len && ctype_digit(substr($data, $i + 1, 3))) {
                    $out .= chr((int) substr($data, $i + 1, 3));
                    $i += 3;
                } else {
                    $out .= $data[++$i];
                }
                continue;
            }
            if ($c === '"') {
                $in = false;
                continue;
            }
            $out .= $c;
        }
        return $out;
    }

    public static function normalizeName(string $name): string {
        return strtolower(rtrim(trim($name), '.'));
    }

    /* Vide les caches et retire les crochets de test. */
    public static function reset(): void {
        self::$directBlocked = false;
        self::$brokenFamily = array();
        self::$nsCache = array();
        self::$nsHosts = array();
        self::$ipHosts = array();
        self::$queryHook = null;
        self::$dohHook = null;
        self::$lookupHook = null;
    }

    protected static function log(?callable $logger, string $level, string $message): void {
        if ($logger === null) {
            return;
        }
        try {
            call_user_func($logger, $level, $message);
        } catch (Throwable $e) {
            // Un journal défaillant ne doit jamais interrompre la vérification.
        }
    }
}

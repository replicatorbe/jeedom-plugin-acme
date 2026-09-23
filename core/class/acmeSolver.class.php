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
 * Solveurs de défis ACME : HTTP-01 (fichier dans la racine web) et DNS-01
 * (enregistrement TXT posé par un fournisseur DNS).
 *
 * Déroulé imposé par acmeClient::issue() : prepare() pour chaque
 * autorisation, waitReady() une fois, puis cleanup() toujours (finally).
 * Indépendant du cœur de Jeedom ; les erreurs lèvent acmeException
 * (acmeClient.class.php).
 */

require_once __DIR__ . '/acmeDns.class.php';

abstract class acmeSolver {

    /** @var callable|null function (string $level, string $message) */
    protected $logger = null;

    public function setLogger(?callable $logger): void {
        $this->logger = $logger;
    }

    /* 'http-01' | 'dns-01' */
    abstract public function getType(): string;

    /* $domain sans le préfixe « *. » (l'identifiant ACME d'un wildcard en est
     * déjà dépourvu). */
    abstract public function prepare(string $domain, string $token, string $keyAuthorization): void;

    /* Attend que tout soit visible de l'extérieur. */
    public function waitReady(): void {
    }

    /* Retire tout ce qui a été posé, sans lever. */
    abstract public function cleanup(): void;

    protected function log(string $level, string $message): void {
        if ($this->logger === null) {
            return;
        }
        try {
            call_user_func($this->logger, $level, $message);
        } catch (Throwable $e) {
            // Un journal défaillant ne doit jamais interrompre l'émission.
        }
    }

    /* Nom de domaine normalisé : minuscules, sans point final ni « *. ». */
    protected static function normalizeDomain(string $domain): string {
        $domain = strtolower(rtrim(trim($domain), '.'));
        if (substr($domain, 0, 2) === '*.') {
            $domain = substr($domain, 2);
        }
        if ($domain === '' || !preg_match('/^[a-z0-9_.-]+$/', $domain)) {
            throw new acmeException('Nom de domaine invalide : ' . $domain);
        }
        return $domain;
    }
}

/*
 * HTTP-01 : l'autorité télécharge
 * http://<domaine>/.well-known/acme-challenge/<token>, toujours sur le port
 * 80 public, et attend exactement keyAuthorization.
 *
 * Racine de Jeedom sous Apache : le .htaccess racine de Jeedom commence par
 * « Order Allow,Deny » sans « Allow », puis n'autorise que certaines
 * extensions (css, js, php, png, txt…). Un fichier sans extension, comme un
 * jeton ACME, y reçoit donc un 403 (vérifié : /LICENSE répond 403, et
 * /.well-known/acme-challenge/x aussi). Le solveur pose donc, dans
 * acme-challenge, un .htaccess qui rouvre l'accès à ce seul dossier (syntaxe
 * 2.2 via mod_access_compat, qu'emploie le .htaccess racine, et 2.4). Il
 * est retiré au nettoyage s'il a été créé par le solveur. Sous nginx, il est
 * simplement ignoré.
 */
class acmeSolverHttp extends acmeSolver {

    const HTACCESS_MARKER = '# géré par le plugin Jeedom acme';

    /* Âge (s) au-delà duquel un fichier de jeton est tenu pour orphelin. */
    const ORPHAN_AGE = 3600;

    /** @var string */
    protected $webroot;

    /* Défis posés : liste de ['domain', 'token', 'keyAuthorization', 'file']. */
    protected $challenges = array();

    /* Dossiers créés par le solveur, du plus profond au moins profond. */
    protected $createdDirs = array();

    /* .htaccess créé (ou repris) par le solveur (chemin), ou null. */
    protected $createdHtaccess = null;

    /* Vrai quand les fichiers orphelins ont déjà été recherchés. */
    protected $purged = false;

    public function __construct(string $webroot) {
        $webroot = rtrim($webroot, '/');
        $this->webroot = $webroot === '' ? '/' : $webroot;
    }

    public function getType(): string {
        return 'http-01';
    }

    public function getChallengeDir(): string {
        return $this->webroot . '/.well-known/acme-challenge';
    }

    public function prepare(string $domain, string $token, string $keyAuthorization): void {
        $domain = self::normalizeDomain($domain);
        // Charset base64url uniquement : aucune traversée de chemin possible.
        if (!preg_match('/^[A-Za-z0-9_-]{1,512}$/', $token)) {
            throw new acmeException('Jeton ACME invalide (caractères non autorisés)');
        }
        if (!preg_match('/^[A-Za-z0-9_.-]{1,2048}$/', $keyAuthorization)) {
            throw new acmeException("Autorisation de clé ACME invalide (caractères non autorisés)");
        }
        if (!is_dir($this->webroot)) {
            throw new acmeException('Racine web introuvable : ' . $this->webroot);
        }

        $wellKnown = $this->webroot . '/.well-known';
        $dir = $wellKnown . '/acme-challenge';
        foreach (array($wellKnown, $dir) as $path) {
            if (is_dir($path)) {
                continue;
            }
            if (file_exists($path)) {
                throw new acmeException($path . " existe mais n'est pas un dossier");
            }
            if (!@mkdir($path, 0755)) {
                throw new acmeException('Impossible de créer ' . $path . ' (droits ?)');
            }
            @chmod($path, 0755);
            array_unshift($this->createdDirs, $path);
            $this->log('debug', 'Dossier créé : ' . $path);
        }

        $htaccess = $dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            if (@file_put_contents($htaccess, self::htaccessContent()) === false) {
                throw new acmeException("Impossible d'écrire " . $htaccess);
            }
            @chmod($htaccess, 0644);
            $this->createdHtaccess = $htaccess;
        } elseif ($this->createdHtaccess === null
            && strpos((string) @file_get_contents($htaccess), self::HTACCESS_MARKER) !== false) {
            // Laissé par un essai interrompu : repris (et remis à jour) pour
            // être retiré au nettoyage.
            @file_put_contents($htaccess, self::htaccessContent());
            $this->createdHtaccess = $htaccess;
            $this->log('debug', '.htaccess laissé par un essai précédent repris : ' . $htaccess);
        }
        $this->purgeOrphans($dir, $token);

        $file = $dir . '/' . $token;
        $tmp = $dir . '/.' . $token . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, $keyAuthorization) === false) {
            throw new acmeException("Impossible d'écrire le fichier de défi dans " . $dir);
        }
        @chmod($tmp, 0644);
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new acmeException("Impossible d'écrire le fichier de défi " . $file);
        }
        $this->challenges[] = array(
            'domain' => $domain,
            'token' => $token,
            'keyAuthorization' => $keyAuthorization,
            'file' => $file,
        );
        $this->log('info', 'Défi HTTP-01 posé pour ' . $domain . ' : /.well-known/acme-challenge/' . $token);
    }

    /* Retire, une fois par solveur, les fichiers de jetons (et temporaires)
     * de plus d'une heure laissés par un essai interrompu. */
    protected function purgeOrphans(string $dir, string $currentToken): void {
        if ($this->purged) {
            return;
        }
        $this->purged = true;
        $entries = @scandir($dir);
        if (!is_array($entries)) {
            return;
        }
        $limit = time() - self::ORPHAN_AGE;
        foreach ($entries as $entry) {
            if ($entry === $currentToken
                || !preg_match('/^(?:[A-Za-z0-9_-]{43}|\.[A-Za-z0-9_-]{43}\.[0-9a-f]{8}\.tmp)$/', $entry)) {
                continue;
            }
            $path = $dir . '/' . $entry;
            $mtime = @filemtime($path);
            if (!is_file($path) || $mtime === false || $mtime > $limit) {
                continue;
            }
            if (@unlink($path)) {
                $this->log('info', "Fichier de défi orphelin d'un essai précédent retiré : " . $path);
            } else {
                $this->log('warning', 'Impossible de retirer le fichier de défi orphelin ' . $path);
            }
        }
    }

    /* .htaccess minimal : rouvre seulement l'accès aux jetons (fichiers sans
     * extension) ; le reste (Options…) est hérité du .htaccess racine. */
    public static function htaccessContent(): string {
        return self::HTACCESS_MARKER . "\n"
            . "# Rend les jetons de validation ACME (HTTP-01) accessibles.\n"
            . "<IfModule mod_access_compat.c>\n"
            . "    Order Allow,Deny\n"
            . "    Allow from all\n"
            . "</IfModule>\n"
            . "<IfModule mod_authz_core.c>\n"
            . "    Require all granted\n"
            . "</IfModule>\n";
    }

    /*
     * Auto-vérification non bloquante : d'abord par le nom (peut échouer sans
     * « NAT loopback » sur le routeur), puis en local avec l'en-tête Host.
     * Jamais d'exception : seule l'autorité juge.
     */
    public function waitReady(): void {
        foreach ($this->challenges as $c) {
            $path = '/.well-known/acme-challenge/' . $c['token'];
            $public = $this->httpGet('http://' . $c['domain'] . $path, array());
            if ($public['code'] == 200 && trim($public['body']) === $c['keyAuthorization']) {
                $this->log('info', 'Défi HTTP-01 joignable via http://' . $c['domain'] . $path);
                continue;
            }
            $local = $this->httpGet('http://127.0.0.1' . $path, array('Host: ' . $c['domain']));
            $localOk = $local['code'] == 200 && trim($local['body']) === $c['keyAuthorization'];
            $publicInfo = $public['error'] !== '' ? $public['error'] : 'HTTP ' . $public['code'];
            if ($localOk) {
                $this->log('warning', 'Défi HTTP-01 servi en local, mais pas via http://' . $c['domain'] . $path
                    . ' (' . $publicInfo . '). Normal si le routeur ne fait pas de « NAT loopback » ; '
                    . "sinon, vérifiez que le port 80 public est redirigé vers ce Jeedom.");
            } else {
                $localInfo = $local['error'] !== '' ? $local['error'] : 'HTTP ' . $local['code'];
                $this->log('warning', 'Défi HTTP-01 introuvable, ni via ' . $c['domain'] . ' (' . $publicInfo
                    . '), ni en local (' . $localInfo . '). Vérifiez la racine web (' . $this->webroot
                    . ') et la configuration du serveur web pour /.well-known/acme-challenge/.');
            }
        }
    }

    /*
     * Transport HTTP, surchargeable (tests). Renvoie
     * ['code' => int, 'body' => string, 'error' => string].
     */
    protected function httpGet(string $url, array $headers): array {
        if (!function_exists('curl_init')) {
            return array('code' => 0, 'body' => '', 'error' => 'extension curl absente');
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
            // Auto-vérification seulement : une redirection vers HTTPS avec un
            // certificat pas encore valide ne doit pas la faire échouer.
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT => 'jeedom-acme (auto-vérification)',
        ));
        $body = curl_exec($ch);
        $result = array(
            'code' => (int) curl_getinfo($ch, CURLINFO_HTTP_CODE),
            'body' => is_string($body) ? $body : '',
            'error' => $body === false ? curl_error($ch) : '',
        );
        curl_close($ch);
        return $result;
    }

    public function cleanup(): void {
        foreach ($this->challenges as $c) {
            if (file_exists($c['file']) && !@unlink($c['file'])) {
                $this->log('error', 'Impossible de supprimer ' . $c['file']);
            }
        }
        $this->challenges = array();
        if ($this->createdHtaccess !== null) {
            if (file_exists($this->createdHtaccess) && !@unlink($this->createdHtaccess)) {
                $this->log('error', 'Impossible de supprimer ' . $this->createdHtaccess);
            }
            $this->createdHtaccess = null;
        }
        foreach ($this->createdDirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            $entries = @scandir($dir);
            if (is_array($entries) && count(array_diff($entries, array('.', '..'))) == 0) {
                if (!@rmdir($dir)) {
                    $this->log('error', 'Impossible de supprimer le dossier ' . $dir);
                }
            } else {
                $this->log('debug', 'Dossier conservé car non vide : ' . $dir);
            }
        }
        $this->createdDirs = array();
    }
}

/*
 * DNS-01 : TXT « _acme-challenge.<domaine> » = b64url(sha256(keyAuthorization)).
 * Plusieurs valeurs peuvent coexister sur le même nom (domaine + wildcard).
 *
 * Si _acme-challenge.<domaine> est un CNAME (délégation de la validation),
 * le TXT est posé sur la cible, que l'autorité atteint en suivant le CNAME.
 *
 * L'autorité ne valide qu'une fois : un TXT absent donne une autorisation
 * invalide, et le nombre d'échecs est limité (environ 5 par heure et par
 * nom). waitReady() lève donc si les serveurs faisant autorité ne voient
 * pas le TXT à l'expiration du délai, plutôt que de laisser échouer la
 * validation.
 */
class acmeSolverDns extends acmeSolver {

    /* Attente minimale après publication avant la première interrogation
     * DNS-over-HTTPS : interroger trop tôt fige une réponse négative dans le
     * cache du résolveur (jusqu'au minimum du SOA, 86400 s chez OVH). */
    const DOH_MIN_DELAY = 90;

    /* Délai de sécurité quand la propagation ne peut pas être vérifiée et
     * qu'aucun délai supplémentaire n'est configuré. */
    const UNKNOWN_SAFETY_DELAY = 60;

    /* Valeur TXT d'un défi ACME (43 caractères base64url), guillemets tolérés.
     * Sert seulement au journal : un TXT n'est jamais retiré d'après sa forme. */
    const ACME_VALUE_PATTERN = '/^"?[A-Za-z0-9_-]{43}"?$/';

    /* Version du format du fichier d'état. */
    const STATE_VERSION = 1;

    /** @var acmeDnsProvider */
    protected $provider;

    protected $options = array();

    /* Enregistrements posés : liste de ['fqdn' (nom réellement écrit, cible
     * du CNAME éventuel), 'value', 'domain', 'name' (_acme-challenge.<domaine>,
     * nom vérifié comme le fait l'autorité), 'id' (identifiant fournisseur ou
     * null)]. */
    protected $records = array();

    /* Enregistrements posés et pas encore retirés, tels que listés dans le
     * fichier d'état : liste de ['fqdn', 'value', 'id', 'created'] ; null tant
     * que le fichier n'a pas été lu. */
    protected $pending = null;

    /* Vrai quand les restes d'une tâche précédente ont été traités. */
    protected $leftoversDone = false;

    /* Noms dont les TXT ont déjà été passés en revue (fqdn => true). */
    protected $inspected = array();

    /* Zones dont les serveurs DNS ont déjà été contrôlés (zone => true). */
    protected $checkedZones = array();

    /* Vrai quand des retraits restent à publier (restes). */
    protected $dirty = false;

    /*
     * options : 'propagationTimeout' (s, défaut 300), 'pollInterval' (s,
     * défaut 10), 'checkPropagation' (bool, défaut true), 'extraDelay' (s,
     * défaut 0), 'stateFile' (chemin d'un fichier JSON, défaut '' : aucun).
     *
     * stateFile liste les TXT posés par le plugin et pas encore retirés. Au
     * premier prepare(), les entrées laissées par une tâche interrompue sont
     * retirées chez le fournisseur ; rien d'autre ne l'est jamais (d'autres
     * outils, certbot par exemple, posent des TXT de même forme sur le même
     * nom). Sans stateFile, aucun reste n'est recherché.
     */
    public function __construct(acmeDnsProvider $provider, array $options = array()) {
        $this->provider = $provider;
        $options = array_merge(array(
            'propagationTimeout' => 300,
            'pollInterval' => 10,
            'checkPropagation' => true,
            'extraDelay' => 0,
            'stateFile' => '',
        ), $options);
        $this->options = array(
            'propagationTimeout' => max(0, (int) $options['propagationTimeout']),
            'pollInterval' => max(1, (int) $options['pollInterval']),
            'checkPropagation' => (bool) $options['checkPropagation'],
            'extraDelay' => max(0, (int) $options['extraDelay']),
            'stateFile' => is_string($options['stateFile']) ? trim($options['stateFile']) : '',
        );
    }

    public function getType(): string {
        return 'dns-01';
    }

    /* Nom de l'enregistrement TXT pour un domaine. */
    public static function recordName(string $domain): string {
        return '_acme-challenge.' . self::normalizeDomain($domain);
    }

    /* Valeur du TXT : b64url(sha256(keyAuthorization)), sans remplissage. */
    public static function recordValue(string $keyAuthorization): string {
        return rtrim(strtr(base64_encode(hash('sha256', $keyAuthorization, true)), '+/', '-_'), '=');
    }

    public function getRecords(): array {
        return $this->records;
    }

    public function prepare(string $domain, string $token, string $keyAuthorization): void {
        $domain = self::normalizeDomain($domain);
        $name = self::recordName($domain);
        $value = self::recordValue($keyAuthorization);
        foreach ($this->records as $r) {
            if ($r['name'] === $name && $r['value'] === $value) {
                return;
            }
        }

        // Délégation par CNAME : le TXT va sur la cible.
        $fqdn = $name;
        $target = null;
        foreach ($this->records as $r) {
            if ($r['name'] === $name) {
                $fqdn = $r['fqdn'];
                break;
            }
        }
        if ($fqdn === $name) {
            $target = $this->resolveTarget($name);
            if ($target !== null) {
                $fqdn = $target;
                $this->log('info', $name . ' est un CNAME vers ' . $target
                    . ' (délégation de la validation) : le TXT est posé sur ' . $target);
            }
        }

        $this->checkNameServers($fqdn);
        $this->removeLeftovers();
        $this->inspectName($fqdn);

        // Retenu (en mémoire et dans le fichier d'état) avant l'appel :
        // cleanup() tentera le retrait même si addTxt() échoue à mi-chemin, et
        // une tâche interrompue laisse un reste listé plutôt qu'un
        // enregistrement inconnu.
        $this->records[] = array('fqdn' => $fqdn, 'value' => $value, 'domain' => $domain, 'name' => $name,
            'id' => null);
        $this->rememberPending($fqdn, $value, null);
        $this->log('info', 'Défi DNS-01 : TXT ' . $fqdn . ' = ' . $value);
        try {
            $this->provider->addTxt($fqdn, $value);
            $id = $this->providerRecordId($fqdn, $value);
            if ($id !== null) {
                $this->records[count($this->records) - 1]['id'] = $id;
                $this->rememberPending($fqdn, $value, $id);
            }
        } catch (Throwable $e) {
            if ($fqdn === $name) {
                throw $e;
            }
            throw new acmeException($name . ' est un CNAME vers ' . $fqdn . ' : le TXT doit être posé sur ' . $fqdn
                . ", mais le fournisseur DNS n'a pas pu le faire (" . $e->getMessage() . '). Donnez au fournisseur '
                . "l'accès à la zone de " . $fqdn . ', ou retirez le CNAME pour poser le TXT directement.',
                array(), 0, $e);
        }
    }

    /*
     * Publie les enregistrements, puis attend que les serveurs faisant
     * autorité les servent tous :
     *  - vus partout : on continue (après extraDelay) ;
     *  - délai écoulé et au moins un TXT absent sur les serveurs d'autorité :
     *    acmeException (la validation échouerait) ;
     *  - délai écoulé sans pouvoir vérifier (serveurs d'autorité injoignables
     *    et DoH en échec, ou DoH seul qui ne voit pas encore la valeur) :
     *    avertissement, puis on continue après extraDelay, ou à défaut après
     *    un délai de sécurité de 60 s.
     */
    public function waitReady(): void {
        if (count($this->records) == 0) {
            return;
        }
        $this->provider->commit();
        $this->dirty = false;
        $committedAt = $this->now();

        if ($this->options['checkPropagation']) {
            $pending = $this->records;
            $last = array();
            $start = $this->now();
            $deferNoted = false;
            $this->log('info', 'Attente de la propagation DNS (' . count($pending) . ' enregistrement(s), '
                . $this->options['propagationTimeout'] . ' s au plus)');
            while (true) {
                $allowDoh = $this->now() - $committedAt >= self::DOH_MIN_DELAY;
                $deferred = false;
                foreach ($pending as $i => $r) {
                    $status = $this->checkStatus($r['name'], $r['value'], $allowDoh);
                    $last[$i] = $status;
                    if ($status['state'] === acmeDnsCheck::VISIBLE) {
                        $this->log('info', 'TXT ' . $r['name'] . ' visible'
                            . ($status['method'] === 'doh' ? ' via DNS-over-HTTPS' : ' sur les serveurs faisant autorité'));
                        unset($pending[$i]);
                    } elseif (!empty($status['deferred'])) {
                        $deferred = true;
                    }
                }
                if (count($pending) == 0) {
                    break;
                }
                if ($deferred) {
                    // DoH nécessaire : première interrogation 90 s après la publication.
                    $wait = self::DOH_MIN_DELAY - ($this->now() - $committedAt);
                    if (!$deferNoted) {
                        $this->log('info', "Serveurs faisant autorité injoignables : vérification par DNS-over-HTTPS "
                            . 'dans ' . max(0, $wait) . " s, pour ne pas figer une réponse négative dans le cache "
                            . 'du résolveur');
                        $deferNoted = true;
                    }
                    $this->sleepSeconds(max(1, $wait));
                    continue;
                }
                if ($this->now() - $start >= $this->options['propagationTimeout']) {
                    $this->propagationTimedOut($pending, $last);
                    break;
                }
                $this->sleepSeconds($this->options['pollInterval']);
            }
        }

        if ($this->options['extraDelay'] > 0) {
            $this->log('info', 'Délai supplémentaire de ' . $this->options['extraDelay'] . ' s');
            $this->sleepSeconds($this->options['extraDelay']);
        }
    }

    /* Délai écoulé : lève si un TXT est absent des serveurs d'autorité,
     * sinon avertit (vérification impossible) et observe un délai de sécurité. */
    protected function propagationTimedOut(array $pending, array $last): void {
        $timeout = $this->options['propagationTimeout'];
        $missing = array();
        $unknown = array();
        foreach ($pending as $i => $r) {
            $status = isset($last[$i]) ? $last[$i] : array('state' => acmeDnsCheck::UNKNOWN, 'servers' => array(),
                'details' => '', 'zone' => null);
            if ($status['state'] === acmeDnsCheck::MISSING) {
                $missing[] = array($r, $status);
            } else {
                $unknown[] = array($r, $status);
            }
        }

        if (count($missing) > 0) {
            $parts = array();
            $zones = array();
            foreach ($missing as $m) {
                list($r, $status) = $m;
                $parts[] = 'TXT ' . $r['name'] . ' = ' . $r['value'] . ' : '
                    . (count($status['servers']) ? implode(' ; ', $status['servers']) : $status['details']);
                if (!empty($status['zone'])) {
                    $zones[$status['zone']] = true;
                }
            }
            $label = $this->providerLabel();
            throw new acmeException('Enregistrement DNS non visible sur les serveurs faisant autorité après '
                . $timeout . ' s. ' . implode('. ', $parts) . '. Validation non demandée : elle échouerait '
                . "(l'autorité ne vérifie qu'une fois, et le nombre d'échecs par heure est limité). Conseils : "
                . 'augmentez le délai de propagation DNS ; vérifiez que les serveurs DNS du domaine'
                . (count($zones) ? ' (zone ' . implode(', ', array_keys($zones)) . ')' : '')
                . ' sont bien ceux de ' . $label . ', chez qui le TXT a été posé.');
        }

        $parts = array();
        foreach ($unknown as $u) {
            list($r, $status) = $u;
            $parts[] = $r['name'] . ' (' . $status['details'] . ')';
        }
        $this->log('warning', 'Propagation DNS impossible à vérifier après ' . $timeout . ' s pour '
            . implode(', ', $parts) . ' : on continue sans confirmation.');
        if ($this->options['extraDelay'] == 0) {
            $this->log('info', 'Délai de sécurité de ' . self::UNKNOWN_SAFETY_DELAY . ' s avant la validation');
            $this->sleepSeconds(self::UNKNOWN_SAFETY_DELAY);
        }
    }

    public function cleanup(): void {
        if (count($this->records) == 0 && !$this->dirty) {
            return;
        }
        foreach ($this->records as $r) {
            try {
                $this->provider->removeTxt($r['fqdn'], $r['value']);
                $this->forgetPending($r['fqdn'], $r['value']);
            } catch (Throwable $e) {
                // Reste listé dans le fichier d'état : retiré à la prochaine tâche.
                $this->log('error', 'Retrait du TXT ' . $r['fqdn'] . ' impossible : ' . $e->getMessage()
                    . ($this->options['stateFile'] !== '' ? ' (nouvel essai à la prochaine tâche)' : ''));
            }
        }
        $this->records = array();
        $this->dirty = false;
        try {
            $this->provider->commit();
        } catch (Throwable $e) {
            $this->log('error', 'Publication de la zone après retrait impossible : ' . $e->getMessage());
        }
    }

    /*
     * Retire, au premier prepare(), les TXT listés dans le fichier d'état :
     * posés par une tâche précédente interrompue avant son nettoyage. Seules
     * ces entrées sont touchées, jamais un TXT reconnu à sa forme. Une entrée
     * que le fournisseur ne connaît plus (retirée à la main) quitte la liste
     * sans erreur ; une entrée dont le retrait échoue y reste (nouvel essai à
     * la prochaine tâche).
     */
    protected function removeLeftovers(): void {
        if ($this->leftoversDone) {
            return;
        }
        $this->leftoversDone = true;
        if ($this->options['stateFile'] === '') {
            return;
        }
        $this->loadPending();
        if (count($this->pending) == 0) {
            return;
        }
        $this->log('info', count($this->pending) . " TXT d'une tâche précédente interrompue à retirer ("
            . $this->options['stateFile'] . ')');
        foreach ($this->pending as $entry) {
            $label = $entry['fqdn'] . ' = ' . $entry['value']
                . ($entry['id'] !== null ? ' (id ' . $entry['id'] . ')' : '')
                . ($entry['created'] !== '' ? ', posé le ' . $entry['created'] : '');
            try {
                if ($entry['id'] !== null && method_exists($this->provider, 'removeTxtById')) {
                    $removed = (bool) $this->provider->removeTxtById($entry['fqdn'], $entry['value'], $entry['id']);
                } else {
                    // Retrait par nom et valeur exacte : un TXT d'une autre
                    // valeur n'est jamais concerné.
                    $this->provider->removeTxt($entry['fqdn'], $entry['value']);
                    $removed = true;
                }
            } catch (Throwable $e) {
                $this->log('warning', "Retrait du reste d'une tâche précédente impossible : " . $label . ' : '
                    . $e->getMessage() . ' (nouvel essai à la prochaine tâche)');
                continue;
            }
            if ($removed) {
                $this->dirty = true;
                $this->log('info', "Reste d'une tâche précédente retiré : " . $label);
            } else {
                $this->log('info', "Reste d'une tâche précédente déjà absent chez le fournisseur, retiré de la liste : "
                    . $label);
            }
            $this->forgetPending($entry['fqdn'], $entry['value']);
        }
    }

    /*
     * Journal seulement, au premier passage sur un nom (si le fournisseur sait
     * lister : listTxt()) : signale les TXT de forme ACME posés par un autre
     * outil, laissés en place.
     */
    protected function inspectName(string $fqdn): void {
        if (isset($this->inspected[$fqdn])) {
            return;
        }
        $this->inspected[$fqdn] = true;
        if (!method_exists($this->provider, 'listTxt')) {
            return;
        }
        try {
            $values = $this->provider->listTxt($fqdn);
        } catch (Throwable $e) {
            $this->log('debug', 'Liste des TXT de ' . $fqdn . ' impossible : ' . $e->getMessage());
            return;
        }
        foreach (is_array($values) ? $values : array() as $v) {
            $v = trim((string) $v);
            if (!preg_match(self::ACME_VALUE_PATTERN, $v)) {
                continue;
            }
            $v = trim($v, '"');
            if ($this->isPending($fqdn, $v)) {
                continue;
            }
            $this->log('debug', "TXT d'un autre outil laissé en place : " . $fqdn . ' = ' . $v);
        }
    }

    /* Identifiant fournisseur du TXT tout juste posé (facultatif :
     * recordId()), ou null. */
    protected function providerRecordId(string $fqdn, string $value): ?string {
        if (!method_exists($this->provider, 'recordId')) {
            return null;
        }
        try {
            $id = $this->provider->recordId($fqdn, $value);
        } catch (Throwable $e) {
            return null;
        }
        return $id === null || $id === '' ? null : (string) $id;
    }

    /* ---------------------------------------------------------------- */
    /* Fichier d'état : {"version": 1, "records": [{"fqdn", "value", "id",
     * "created"}]}. Écrit en 0600, par fichier temporaire et rename(). */

    /* Lit le fichier d'état une fois ; illisible ou invalide : liste vide. */
    protected function loadPending(): void {
        if ($this->pending !== null) {
            return;
        }
        $this->pending = array();
        $file = $this->options['stateFile'];
        if ($file === '' || !file_exists($file)) {
            return;
        }
        $raw = @file_get_contents($file);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data) || !isset($data['records']) || !is_array($data['records'])) {
            $this->log('warning', "Fichier d'état DNS illisible, ignoré (les restes éventuels d'une tâche "
                . 'précédente ne seront pas retirés) : ' . $file);
            return;
        }
        foreach ($data['records'] as $r) {
            if (!is_array($r) || !isset($r['fqdn'], $r['value']) || !is_string($r['fqdn']) || !is_string($r['value'])
                || $r['fqdn'] === '' || $r['value'] === '') {
                continue;
            }
            $id = isset($r['id']) && (is_string($r['id']) || is_int($r['id'])) && (string) $r['id'] !== ''
                ? (string) $r['id'] : null;
            $this->pending[] = array(
                'fqdn' => $r['fqdn'],
                'value' => $r['value'],
                'id' => $id,
                'created' => isset($r['created']) && is_string($r['created']) ? $r['created'] : '',
            );
        }
    }

    protected function isPending(string $fqdn, string $value): bool {
        foreach (is_array($this->pending) ? $this->pending : array() as $p) {
            if ($p['fqdn'] === $fqdn && $p['value'] === $value) {
                return true;
            }
        }
        return false;
    }

    /* Ajoute (ou complète de son identifiant) une entrée, puis écrit. */
    protected function rememberPending(string $fqdn, string $value, ?string $id): void {
        if ($this->options['stateFile'] === '') {
            return;
        }
        $this->loadPending();
        foreach ($this->pending as $i => $p) {
            if ($p['fqdn'] === $fqdn && $p['value'] === $value) {
                if ($id === null || $p['id'] === $id) {
                    return;
                }
                $this->pending[$i]['id'] = $id;
                $this->savePending();
                return;
            }
        }
        $this->pending[] = array('fqdn' => $fqdn, 'value' => $value, 'id' => $id, 'created' => date('c', $this->now()));
        $this->savePending();
    }

    /* Retire une entrée, puis écrit. */
    protected function forgetPending(string $fqdn, string $value): void {
        if ($this->options['stateFile'] === '') {
            return;
        }
        $this->loadPending();
        $kept = array();
        foreach ($this->pending as $p) {
            if ($p['fqdn'] !== $fqdn || $p['value'] !== $value) {
                $kept[] = $p;
            }
        }
        if (count($kept) == count($this->pending)) {
            return;
        }
        $this->pending = $kept;
        $this->savePending();
    }

    /* Écrit la liste (atomique, 0600) ; liste vide : fichier supprimé. Une
     * erreur d'écriture est signalée sans interrompre l'émission. */
    protected function savePending(): void {
        $file = $this->options['stateFile'];
        if (count($this->pending) == 0) {
            if (file_exists($file) && !@unlink($file)) {
                $this->log('warning', "Impossible de supprimer le fichier d'état DNS " . $file);
            }
            return;
        }
        $dir = dirname($file);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            $this->log('warning', "Impossible de créer le dossier du fichier d'état DNS : " . $dir);
            return;
        }
        $json = json_encode(array('version' => self::STATE_VERSION, 'records' => array_values($this->pending)),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        // tempnam() crée le fichier en 0600, dans le même dossier (rename atomique).
        $tmp = @tempnam($dir, '.dns_pending.');
        if ($tmp === false || realpath(dirname($tmp)) !== realpath($dir)) {
            if (is_string($tmp)) {
                @unlink($tmp);
            }
            $this->log('warning', "Impossible d'écrire le fichier d'état DNS dans " . $dir);
            return;
        }
        @chmod($tmp, 0600);
        if (@file_put_contents($tmp, $json . "\n") === false || !@rename($tmp, $file)) {
            @unlink($tmp);
            $this->log('warning', "Impossible d'écrire le fichier d'état DNS " . $file);
            return;
        }
        @chmod($file, 0600);
    }

    /*
     * Avertit, une fois par zone, si ses serveurs DNS ne ressemblent pas à
     * ceux du fournisseur (s'il les annonce : expectedNameServers()).
     */
    protected function checkNameServers(string $fqdn): void {
        if (!method_exists($this->provider, 'expectedNameServers')) {
            return;
        }
        try {
            $suffixes = $this->provider->expectedNameServers();
            $info = $this->nameServers($fqdn);
        } catch (Throwable $e) {
            $this->log('debug', 'Contrôle des serveurs DNS de ' . $fqdn . ' impossible : ' . $e->getMessage());
            return;
        }
        $zone = isset($info['zone']) ? (string) $info['zone'] : '';
        $hosts = isset($info['hosts']) && is_array($info['hosts']) ? $info['hosts'] : array();
        if (!is_array($suffixes) || count($suffixes) == 0 || $zone === '' || count($hosts) == 0
            || isset($this->checkedZones[$zone])) {
            return;
        }
        $this->checkedZones[$zone] = true;
        foreach ($hosts as $host) {
            $host = strtolower(rtrim((string) $host, '.'));
            foreach ($suffixes as $suffix) {
                $suffix = strtolower(trim((string) $suffix, '.*'));
                if ($suffix !== '' && ($host === $suffix || substr($host, -strlen($suffix) - 1) === '.' . $suffix)) {
                    return;
                }
            }
        }
        $label = $this->providerLabel();
        $this->log('warning', 'Les serveurs DNS de la zone ' . $zone . ' (' . implode(', ', $hosts)
            . ') ne ressemblent pas à ceux de ' . $label . ' (' . implode(', ', $suffixes) . ') : le TXT posé chez '
            . $label . " risque de ne pas être vu par l'autorité. Vérifiez les serveurs DNS déclarés chez le "
            . 'registraire du domaine.');
    }

    protected function providerLabel(): string {
        try {
            $class = get_class($this->provider);
            return (string) $class::getLabel();
        } catch (Throwable $e) {
            return 'le fournisseur DNS';
        }
    }

    /* Cible du CNAME de délégation, ou null ; surchargeable (tests). */
    protected function resolveTarget(string $name): ?string {
        try {
            $target = acmeDnsCheck::cnameTarget($name, $this->logger);
        } catch (Throwable $e) {
            $this->log('warning', 'Résolution du CNAME éventuel de ' . $name . ' impossible : ' . $e->getMessage());
            return null;
        }
        if ($target === null || !preg_match('/^[a-z0-9_.-]+$/', $target)) {
            return null;
        }
        return $target;
    }

    /* Zone et serveurs DNS d'un nom : ['zone' => ?string, 'hosts' => string[]] ;
     * surchargeable (tests). */
    protected function nameServers(string $fqdn): array {
        $zone = null;
        $hosts = acmeDnsCheck::authoritativeNameServers($fqdn, $this->logger, $zone);
        return array('zone' => $zone, 'hosts' => $hosts);
    }

    /* État de visibilité (format acmeDnsCheck::txtStatus()), surchargeable
     * (tests). Une erreur inattendue vaut « impossible à vérifier ». */
    protected function checkStatus(string $fqdn, string $value, bool $allowDoh): array {
        try {
            return acmeDnsCheck::txtStatus($fqdn, $value, $this->logger, $allowDoh);
        } catch (Throwable $e) {
            $this->log('debug', 'Vérification DNS de ' . $fqdn . ' en échec : ' . $e->getMessage());
            return array('state' => acmeDnsCheck::UNKNOWN, 'method' => 'none', 'zone' => null, 'name' => $fqdn,
                'servers' => array(), 'deferred' => false, 'details' => 'vérification en échec : ' . $e->getMessage());
        }
    }

    /* Horloge, surchargeable (tests). */
    protected function now(): int {
        return time();
    }

    /* Attente, surchargeable (tests). */
    protected function sleepSeconds(int $seconds): void {
        if ($seconds > 0) {
            sleep($seconds);
        }
    }
}

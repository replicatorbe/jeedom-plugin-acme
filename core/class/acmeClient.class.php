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

require_once __DIR__ . '/acmeCrypto.class.php';

/*
 * Erreur du client ACME. Porte, quand l'autorité en a renvoyé un, le document
 * problème (RFC 7807 / RFC 8555 §6.7) : type, detail, subproblems…
 */
class acmeException extends Exception {

    /** @var array */
    private $problem;

    public function __construct(string $message, array $problem = array(), int $code = 0, ?Throwable $previous = null) {
        parent::__construct($message, $code, $previous);
        $this->problem = $problem;
    }

    /** Document problème ACME, ou tableau vide. */
    public function getProblem(): array {
        return $this->problem;
    }
}

/*
 * Client ACME (RFC 8555), sans dépendance : curl, openssl et json seulement,
 * aucune classe du cœur de Jeedom.
 *
 * Usage :
 *   $client = new acmeClient(acmeClient::LETSENCRYPT, $accountKeyPem, $logger);
 *   $client->registerAccount('moi@example.org');     // ou setAccountUrl()
 *   $res = $client->issue(array('example.org'), $certKeyPem, $solver);
 *
 * Le journal est un callable function (string $level, string $message) ;
 * aucun secret n'y est écrit (ni clé, ni corps JWS, ni HMAC EAB).
 */
class acmeClient {

    const LETSENCRYPT         = 'https://acme-v02.api.letsencrypt.org/directory';
    const LETSENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';
    const ZEROSSL             = 'https://acme.zerossl.com/v2/DV90';

    const VERSION = '0.1';
    const USER_AGENT = 'jeedom-acme/' . self::VERSION;

    /* Délais (secondes). */
    const HTTP_CONNECT_TIMEOUT = 15;
    const HTTP_TIMEOUT = 45;
    const AUTHZ_TIMEOUT = 180;      // attente de la validation de toutes les autorisations
    const ORDER_TIMEOUT = 180;      // attente de l'ordre (ready puis valid)
    const MAX_RETRY_AFTER = 60;     // borne d'un Retry-After respecté
    const BAD_NONCE_RETRIES = 5;
    const SERVER_RETRIES = 3;       // 5xx / 429 avec Retry-After court
    const NETWORK_RETRIES = 3;      // erreurs de transport sur requête rejouable (attentes 2, 4, 8 s)

    /* Code porté par l'acmeException d'une erreur de transport (coupure, délai
     * curl, DNS…) : aucune réponse HTTP reçue, d'où un code hors plage HTTP. */
    const NETWORK_ERROR = 1;

    const ZEROSSL_EAB_URL = 'https://api.zerossl.com/acme/eab-credentials-email';

    /** @var string */
    private $directoryUrl;
    /** @var string */
    private $accountKey;
    /** @var callable|null */
    private $logger;
    /** @var array|null */
    private $directory = null;
    /** @var string|null */
    private $nonce = null;
    /** @var string|null */
    private $accountUrl = null;
    /** @var string|null */
    private $thumbprint = null;

    public function __construct(string $directoryUrl, string $accountKeyPem, ?callable $logger = null) {
        $this->directoryUrl = $directoryUrl;
        $this->accountKey = $accountKeyPem;
        $this->logger = $logger;
    }

    /* ------------------------------------------------------------------ */
    /* Annuaire et compte                                                  */
    /* ------------------------------------------------------------------ */

    /** Annuaire de l'autorité (mis en cache pour la durée de vie de l'objet). */
    public function getDirectory(): array {
        if ($this->directory === null) {
            $res = $this->httpWithRetry('GET', $this->directoryUrl);
            if ($res['status'] !== 200) {
                $this->throwProblem($res, 'Annuaire ACME inaccessible (' . $this->directoryUrl . ')');
            }
            $dir = json_decode($res['body'], true);
            if (!is_array($dir) || !isset($dir['newNonce'], $dir['newAccount'], $dir['newOrder'])) {
                throw new acmeException('Réponse invalide : ' . $this->directoryUrl . ' n\'est pas un annuaire ACME');
            }
            $this->directory = $dir;
        }
        return $this->directory;
    }

    /** Vrai si l'autorité exige un rattachement de compte externe (EAB). */
    public function requiresEab(): bool {
        $dir = $this->getDirectory();
        return !empty($dir['meta']['externalAccountRequired']);
    }

    /**
     * Crée le compte, ou retrouve celui qui correspond à la clé. Renvoie l'URL
     * du compte (kid). $email peut être vide (aucun contact n'est alors envoyé).
     */
    public function registerAccount(string $email, ?string $eabKid = null, ?string $eabHmacKey = null): string {
        $dir = $this->getDirectory();
        $payload = array('termsOfServiceAgreed' => true);
        $email = trim($email);
        if ($email !== '') {
            $payload['contact'] = array('mailto:' . $email);
        }
        $hasEab = ($eabKid !== null && $eabKid !== '' && $eabHmacKey !== null && $eabHmacKey !== '');
        if ($hasEab) {
            $this->log('debug', 'Rattachement EAB, kid ' . self::mask($eabKid) . ', clé HMAC ' . self::mask($eabHmacKey));
            $payload['externalAccountBinding'] = $this->eabJws($eabKid, $eabHmacKey, $dir['newAccount']);
        } elseif ($this->requiresEab()) {
            // Sans EAB, l'autorité ne peut que retrouver un compte existant.
            try {
                $res = $this->signedRequest($dir['newAccount'], array('onlyReturnExisting' => true), true);
            } catch (acmeException $e) {
                throw new acmeException('Cette autorité exige des identifiants EAB (kid et clé HMAC) pour créer un compte', $e->getProblem(), 0, $e);
            }
            return $this->acceptAccount($res, false);
        }
        $res = $this->signedRequest($dir['newAccount'], $payload, true);
        return $this->acceptAccount($res, true);
    }

    /** Fixe l'URL du compte déjà connue (évite un appel à newAccount). */
    public function setAccountUrl(string $url): void {
        $this->accountUrl = $url;
    }

    /** URL du compte, ou null si ni registerAccount() ni setAccountUrl() n'ont été appelés. */
    public function getAccountUrl(): ?string {
        return $this->accountUrl;
    }

    /**
     * Remplace le contact du compte (RFC 8555 §7.3.2). $email vide : le compte
     * n'a plus de contact. Rejouable sans risque (même état final).
     * Let's Encrypt accepte la requête mais ne conserve plus les adresses et
     * n'en renvoie aucune dans l'objet compte : seul le statut est vérifié.
     */
    public function updateContact(string $email): void {
        $this->requireAccount();
        $email = trim($email);
        $contact = $email === '' ? array() : array('mailto:' . $email);
        $res = $this->signedRequest($this->accountUrl, array('contact' => $contact), false, array(), true);
        $account = self::decodeJson($res, 'mise à jour du contact');
        if (isset($account['status']) && $account['status'] !== 'valid') {
            throw new acmeException('Compte ACME dans l\'état « ' . $account['status'] . ' »');
        }
        $this->log('info', $email === '' ? 'Contact du compte ACME supprimé' : 'Contact du compte ACME mis à jour');
    }

    /**
     * Désactive définitivement le compte (RFC 8555 §7.3.6) : l'autorité refusera
     * ensuite toute requête signée par sa clé. Irréversible.
     */
    public function deactivateAccount(): void {
        $this->requireAccount();
        // Rejouable : une seconde désactivation ne change rien (au pire, refus
        // « unauthorized » si la première était passée).
        $res = $this->signedRequest($this->accountUrl, array('status' => 'deactivated'), false, array(), true);
        $account = self::decodeJson($res, 'désactivation du compte');
        if (!isset($account['status']) || $account['status'] !== 'deactivated') {
            throw new acmeException('Désactivation du compte non confirmée par l\'autorité');
        }
        $this->log('info', 'Compte ACME désactivé : ' . $this->accountUrl);
    }

    /**
     * Classe une erreur liée au compte, pour que l'appelant sache s'il doit en
     * recréer un :
     *   'missing'     : l'autorité ne connaît pas (ou plus) ce compte, ou l'URL
     *                   de compte (kid) ne correspond pas à la clé ;
     *   'deactivated' : le compte existe mais est désactivé ;
     *   ''            : autre erreur (réseau, défi, quota…).
     * Messages relevés sur Let's Encrypt staging :
     *   [malformed] Unable to validate JWS :: JWS verification error
     *   [unauthorized] Account is not valid, has status "deactivated"
     *   [unauthorized] An account with the provided public key exists but is deactivated
     */
    public static function isAccountProblem(Throwable $e): string {
        // Le document problème peut être porté par une exception enveloppée.
        $problem = array();
        for ($x = $e; $x !== null; $x = $x->getPrevious()) {
            if ($x instanceof acmeException && count($x->getProblem())) {
                $problem = $x->getProblem();
                break;
            }
        }
        if (!isset($problem['type'])) {
            return '';
        }
        $type = preg_replace('/^urn:ietf:params:acme:error:/', '', (string) $problem['type']);
        $detail = isset($problem['detail']) ? (string) $problem['detail'] : '';
        if ($type === 'accountDoesNotExist') {
            return 'missing';
        }
        if ($type === 'malformed' && preg_match('/JWS verification|Key ID|KeyID|invalid account|account URL|account not found|no such account/i', $detail)) {
            return 'missing';
        }
        if ($type === 'unauthorized' && preg_match('/deactivated|account is not valid|revoked/i', $detail)) {
            return 'deactivated';
        }
        return '';
    }

    /* ------------------------------------------------------------------ */
    /* Émission                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Émission complète d'un certificat pour $domains avec la clé $certKeyPem.
     * Renvoie ['fullchain' => PEM, 'cert' => PEM feuille, 'chain' => PEM
     * intermédiaires, 'url' => URL du certificat].
     */
    public function issue(array $domains, string $certKeyPem, acmeSolver $solver): array {
        $domains = self::normalizeDomains($domains);
        $this->requireAccount();
        $type = $solver->getType();

        $order = $this->newOrder($domains);
        $orderUrl = $order['url'];
        $this->log('info', 'Commande créée pour ' . implode(', ', $domains) . ' (défi ' . $type . ')');

        // Autorisations : on relève d'abord tout ce qu'il faut valider.
        $pending = array();
        foreach ($order['authorizations'] as $authzUrl) {
            $authz = $this->fetch($authzUrl);
            $domain = isset($authz['identifier']['value']) ? $authz['identifier']['value'] : '?';
            $label = (!empty($authz['wildcard']) ? '*.' : '') . $domain;
            $status = isset($authz['status']) ? $authz['status'] : '';
            if ($status === 'valid') {
                $this->log('info', 'Autorisation déjà valide pour ' . $label . ', défi inutile');
                continue;
            }
            if ($status !== 'pending') {
                throw new acmeException('Autorisation dans un état inattendu pour ' . $label . ' : ' . $status,
                    self::authzProblem($authz));
            }
            $challenge = null;
            foreach ((isset($authz['challenges']) ? $authz['challenges'] : array()) as $c) {
                if (isset($c['type']) && $c['type'] === $type) {
                    $challenge = $c;
                    break;
                }
            }
            if ($challenge === null) {
                $offered = array();
                foreach ((isset($authz['challenges']) ? $authz['challenges'] : array()) as $c) {
                    $offered[] = isset($c['type']) ? $c['type'] : '?';
                }
                throw new acmeException('L\'autorité ne propose pas le défi ' . $type . ' pour ' . $label
                    . ' (proposés : ' . implode(', ', $offered) . ')'
                    . (!empty($authz['wildcard']) ? ' ; un wildcard exige dns-01' : ''));
            }
            $pending[] = array(
                'authz' => $authzUrl,
                'challenge' => $challenge['url'],
                'domain' => $domain,
                'label' => $label,
                'token' => $challenge['token'],
            );
        }

        if (count($pending) > 0) {
            $thumb = $this->accountThumbprint();
            try {
                foreach ($pending as $p) {
                    $this->log('debug', 'Préparation du défi ' . $type . ' pour ' . $p['label']);
                    $this->callSolver(function () use ($solver, $p, $thumb) {
                        $solver->prepare($p['domain'], $p['token'], $p['token'] . '.' . $thumb);
                    }, 'préparation du défi pour ' . $p['label']);
                }
                $this->callSolver(function () use ($solver) {
                    $solver->waitReady();
                }, 'attente de la visibilité des défis');

                foreach ($pending as $p) {
                    $this->signedRequest($p['challenge'], new stdClass());
                    $this->log('debug', 'Défi signalé prêt à l\'autorité pour ' . $p['label']);
                }
                $this->waitAuthorizations($pending);
            } finally {
                try {
                    $solver->cleanup();
                } catch (Throwable $e) {
                    $this->log('warning', 'Nettoyage des défis incomplet : ' . $e->getMessage());
                }
            }
        }

        // Finalisation.
        $order = $this->pollOrder($orderUrl, array('ready', 'valid'), array('pending'), 'prête');
        if ($order['status'] === 'ready') {
            $this->log('debug', 'Envoi de la demande de certificat (CSR)');
            try {
                $csr = acmeCrypto::csr($certKeyPem, $domains);
            } catch (acmeException $e) {
                throw $e;
            } catch (Throwable $e) {
                throw new acmeException('CSR impossible : ' . $e->getMessage(), array(), 0, $e);
            }
            $order = $this->finalizeOrder($order['finalize'], $orderUrl, $csr);
        }
        if (empty($order['certificate'])) {
            throw new acmeException('Commande valide mais sans URL de certificat');
        }

        // Téléchargement.
        $res = $this->signedRequest($order['certificate'], null, false, array('Accept: application/pem-certificate-chain'));
        $certs = acmeCrypto::splitChain($res['body']);
        if (count($certs) === 0) {
            throw new acmeException('Certificat téléchargé illisible');
        }
        $leaf = array_shift($certs);
        $chain = implode('', $certs);
        try {
            $info = acmeCrypto::certInfo($leaf);
            $this->log('info', 'Certificat émis pour ' . implode(', ', $info['domains'])
                . ', valable jusqu\'au ' . gmdate('Y-m-d H:i', $info['notAfter']) . ' UTC (' . $info['issuer'] . ')');
        } catch (Throwable $e) {
            $this->log('info', 'Certificat émis');
        }
        return array(
            'fullchain' => $leaf . $chain,
            'cert' => $leaf,
            'chain' => $chain,
            'url' => $order['certificate'],
        );
    }

    /** Révoque un certificat (raison RFC 5280 : 0 non précisée, 1 clé compromise, 4 remplacé, 5 cessation…). */
    public function revoke(string $certPem, int $reason = 0): void {
        $dir = $this->getDirectory();
        if (empty($dir['revokeCert'])) {
            throw new acmeException('L\'autorité ne publie pas de point de révocation');
        }
        $this->requireAccount();
        $certs = acmeCrypto::splitChain($certPem);
        if (count($certs) === 0) {
            throw new acmeException('Certificat à révoquer illisible');
        }
        $this->signedRequest($dir['revokeCert'], array(
            'certificate' => acmeCrypto::b64url(acmeCrypto::pemToDer($certs[0])),
            'reason' => $reason,
        ));
        $this->log('info', 'Certificat révoqué (raison ' . $reason . ')');
    }

    /* ------------------------------------------------------------------ */
    /* Opérations élémentaires (publiques : utiles aux tests et diagnostics) */
    /* ------------------------------------------------------------------ */

    /** Crée une commande. Renvoie l'objet ordre, augmenté de 'url'. */
    public function newOrder(array $domains): array {
        $this->requireAccount();
        $identifiers = array();
        foreach (self::normalizeDomains($domains) as $d) {
            $identifiers[] = array('type' => 'dns', 'value' => $d);
        }
        $res = $this->signedRequest($this->getDirectory()['newOrder'], array('identifiers' => $identifiers));
        $order = self::decodeJson($res, 'nouvelle commande');
        if (empty($res['headers']['location']) || empty($order['authorizations']) || empty($order['finalize'])) {
            throw new acmeException('Réponse invalide à la création de la commande');
        }
        $order['url'] = $res['headers']['location'];
        return $order;
    }

    /** POST-as-GET sur une ressource JSON (ordre, autorisation, défi, compte). */
    public function fetch(string $url): array {
        return self::decodeJson($this->signedRequest($url, null), $url);
    }

    /** Désactive une autorisation encore en attente (RFC 8555 §7.5.2). */
    public function deactivateAuthorization(string $authzUrl): array {
        $res = $this->signedRequest($authzUrl, array('status' => 'deactivated'));
        return self::decodeJson($res, 'désactivation');
    }

    /* ------------------------------------------------------------------ */
    /* ZeroSSL                                                             */
    /* ------------------------------------------------------------------ */

    /** Identifiants EAB ZeroSSL à partir d'une adresse e-mail : ['kid' => ..., 'hmac' => ...]. */
    public static function zerosslEab(string $email): array {
        $email = trim($email);
        if ($email === '' || strpos($email, '@') === false) {
            throw new acmeException('ZeroSSL : une adresse e-mail valide est nécessaire pour obtenir les identifiants EAB');
        }
        $res = self::httpRaw('POST', self::ZEROSSL_EAB_URL, http_build_query(array('email' => $email)),
            array('Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'));
        $data = json_decode($res['body'], true);
        if ($res['status'] === 200 && is_array($data) && !empty($data['eab_kid']) && !empty($data['eab_hmac_key'])) {
            return array('kid' => (string) $data['eab_kid'], 'hmac' => (string) $data['eab_hmac_key']);
        }
        $detail = '';
        if (is_array($data) && isset($data['error'])) {
            $err = $data['error'];
            $detail = is_array($err)
                ? trim((isset($err['type']) ? $err['type'] : '') . ' ' . (isset($err['info']) ? $err['info'] : '') . ' ' . (isset($err['code']) ? '(' . $err['code'] . ')' : ''))
                : (string) $err;
        }
        throw new acmeException('ZeroSSL : impossible d\'obtenir les identifiants EAB (HTTP ' . $res['status'] . ')'
            . ($detail !== '' ? ' : ' . $detail : ''), is_array($data) ? $data : array());
    }

    /* ------------------------------------------------------------------ */
    /* Déroulé interne                                                     */
    /* ------------------------------------------------------------------ */

    /** Interroge les autorisations jusqu'à ce qu'elles soient toutes valides (délai croissant, borné). */
    private function waitAuthorizations(array $pending): void {
        $deadline = time() + self::AUTHZ_TIMEOUT;
        $delay = 1;
        $left = $pending;
        while (true) {
            $retryAfter = 0;
            foreach ($left as $i => $p) {
                $res = $this->signedRequest($p['authz'], null);
                $authz = self::decodeJson($res, 'autorisation');
                $status = isset($authz['status']) ? $authz['status'] : '';
                if ($status === 'valid') {
                    $this->log('info', 'Défi validé pour ' . $p['label']);
                    unset($left[$i]);
                } elseif ($status === 'pending') {
                    $retryAfter = max($retryAfter, self::retryAfter($res));
                } else {
                    $problem = self::authzProblem($authz);
                    throw new acmeException('Défi refusé pour ' . $p['label'] . ' (' . $status . ')'
                        . (count($problem) ? ' : ' . self::describeProblem($problem) : ''), $problem);
                }
            }
            if (count($left) === 0) {
                return;
            }
            if (time() >= $deadline) {
                $labels = array();
                foreach ($left as $p) {
                    $labels[] = $p['label'];
                }
                throw new acmeException('Délai dépassé (' . self::AUTHZ_TIMEOUT . ' s) en attendant la validation de : ' . implode(', ', $labels));
            }
            $this->pause(max($delay, $retryAfter), $deadline);
            $delay = min($delay * 2, 10);
        }
    }

    /** Interroge l'ordre jusqu'à un état de $okStatuses ; lève sur tout état hors $waitStatuses. */
    private function pollOrder(string $orderUrl, array $okStatuses, array $waitStatuses, string $what, int $firstWait = 0): array {
        $deadline = time() + self::ORDER_TIMEOUT;
        $delay = 1;
        if ($firstWait > 0) {
            $this->pause($firstWait, $deadline);
        }
        while (true) {
            $res = $this->signedRequest($orderUrl, null);
            $order = self::decodeJson($res, 'commande');
            $status = isset($order['status']) ? $order['status'] : '';
            if (in_array($status, $okStatuses, true)) {
                return $order;
            }
            if (!in_array($status, $waitStatuses, true)) {
                $problem = isset($order['error']) && is_array($order['error']) ? $order['error'] : array();
                throw new acmeException('Commande dans l\'état « ' . $status . ' » au lieu de « ' . $what . ' »'
                    . (count($problem) ? ' : ' . self::describeProblem($problem) : ''), $problem);
            }
            if (time() >= $deadline) {
                throw new acmeException('Délai dépassé (' . self::ORDER_TIMEOUT . ' s) : commande toujours « ' . $status . ' »');
            }
            $this->pause(max($delay, self::retryAfter($res)), $deadline);
            $delay = min($delay * 2, 10);
        }
    }

    /**
     * Envoie la CSR puis attend l'ordre « valid ». La finalisation n'est pas
     * rejouée à l'aveugle : si la réponse s'est perdue en route, l'autorité a
     * peut-être déjà accepté la CSR, et un second envoi serait refusé
     * (orderNotReady). On relit donc l'ordre : « processing » ou « valid »
     * signifie que le premier envoi est passé ; toujours « ready », rien n'a
     * été reçu et on renvoie la CSR, une fois par essai réseau autorisé.
     */
    private function finalizeOrder(string $finalizeUrl, string $orderUrl, string $csr): array {
        $payload = array('csr' => acmeCrypto::b64url($csr));
        for ($attempt = 0; ; $attempt++) {
            try {
                $res = $this->signedRequest($finalizeUrl, $payload);
            } catch (acmeException $e) {
                if ($e->getCode() !== self::NETWORK_ERROR || $attempt >= self::NETWORK_RETRIES) {
                    throw $e;
                }
                $wait = 2 << $attempt;
                $this->log('warning', 'Finalisation sans réponse (' . $e->getMessage() . '), relecture de la commande dans ' . $wait . ' s');
                sleep($wait);
                $order = self::decodeJson($this->signedRequest($orderUrl, null), 'commande');
                $status = isset($order['status']) ? $order['status'] : '';
                if ($status === 'valid') {
                    return $order;
                }
                if ($status === 'processing') {
                    return $this->pollOrder($orderUrl, array('valid'), array('processing'), 'émise');
                }
                if ($status !== 'ready') {
                    $problem = isset($order['error']) && is_array($order['error']) ? $order['error'] : array();
                    throw new acmeException('Commande dans l\'état « ' . $status . ' » après une finalisation sans réponse'
                        . (count($problem) ? ' : ' . self::describeProblem($problem) : ''), $problem);
                }
                continue;   // toujours « ready » : la CSR n'a pas été reçue
            }
            $order = self::decodeJson($res, 'finalisation');
            if (!isset($order['status']) || $order['status'] !== 'valid') {
                $order = $this->pollOrder($orderUrl, array('valid'), array('ready', 'processing'), 'émise',
                    self::retryAfter($res));
            }
            return $order;
        }
    }

    /** Appelle le solveur en convertissant ses erreurs en acmeException. */
    private function callSolver(callable $fn, string $what): void {
        try {
            $fn();
        } catch (acmeException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new acmeException('Échec de la ' . $what . ' : ' . $e->getMessage(), array(), 0, $e);
        }
    }

    private function requireAccount(): void {
        if ($this->accountUrl === null || $this->accountUrl === '') {
            throw new acmeException('Compte ACME inconnu : appeler registerAccount() ou setAccountUrl() d\'abord');
        }
    }

    private function accountThumbprint(): string {
        if ($this->thumbprint === null) {
            $this->thumbprint = acmeCrypto::thumbprint($this->accountKey);
        }
        return $this->thumbprint;
    }

    private function acceptAccount(array $res, bool $mayCreate): string {
        if (empty($res['headers']['location'])) {
            throw new acmeException('Réponse invalide : l\'autorité n\'a pas renvoyé l\'URL du compte');
        }
        $this->accountUrl = $res['headers']['location'];
        $account = json_decode($res['body'], true);
        if (is_array($account) && isset($account['status']) && $account['status'] !== 'valid') {
            throw new acmeException('Compte ACME dans l\'état « ' . $account['status'] . ' »');
        }
        $this->log('info', ($res['status'] === 201 && $mayCreate ? 'Compte ACME créé' : 'Compte ACME retrouvé') . ' : ' . $this->accountUrl);
        return $this->accountUrl;
    }

    /** JWS EAB (RFC 8555 §7.3.4) : HS256 sur le JWK du compte, clé HMAC en base64url. */
    private function eabJws(string $kid, string $hmacKey, string $newAccountUrl): array {
        try {
            $key = acmeCrypto::b64urlDecode($hmacKey);
        } catch (Throwable $e) {
            throw new acmeException('Clé HMAC EAB invalide (base64url attendu)');
        }
        $protected = acmeCrypto::b64url(acmeCrypto::jsonEncode(array(
            'alg' => 'HS256',
            'kid' => $kid,
            'url' => $newAccountUrl,
        )));
        $payload = acmeCrypto::b64url(acmeCrypto::jsonEncode(acmeCrypto::jwk($this->accountKey)));
        return array(
            'protected' => $protected,
            'payload' => $payload,
            'signature' => acmeCrypto::b64url(hash_hmac('sha256', $protected . '.' . $payload, $key, true)),
        );
    }

    /* ------------------------------------------------------------------ */
    /* JWS et HTTP                                                         */
    /* ------------------------------------------------------------------ */

    /**
     * Requête signée. $payload null = POST-as-GET (charge utile vide).
     * $useJwk : clé publique dans l'en-tête (newAccount) au lieu du kid.
     * Réessaie sur badNonce et sur les erreurs serveur passagères ; lève
     * une acmeException portant le document problème sur toute erreur.
     *
     * Erreur de transport (aucune réponse) : on ne sait pas si l'autorité a
     * reçu la requête. On ne la rejoue donc que si elle est sans effet ou
     * idempotente : POST-as-GET, réponse à un défi (charge utile « {} », un
     * second envoi ne change rien), ou $replayable explicite (mise à jour du
     * compte). newAccount, newOrder, revokeCert et finalize ne sont jamais
     * rejoués ici : un doublon créerait un second ordre ou serait refusé ;
     * finalize a son propre rattrapage (finalizeOrder, qui relit l'ordre).
     */
    private function signedRequest(string $url, $payload, bool $useJwk = false, array $headers = array(), bool $replayable = false): array {
        $badNonce = 0;
        $server = 0;
        $network = 0;
        if ($payload === null || ($payload instanceof stdClass && count(get_object_vars($payload)) === 0)) {
            $replayable = true;
        }
        while (true) {
            $body = $this->jws($url, $payload, $useJwk);
            try {
                $res = self::httpRaw('POST', $url, $body, array_merge(array('Content-Type: application/jose+json'), $headers));
            } catch (acmeException $e) {
                if (!$replayable || $e->getCode() !== self::NETWORK_ERROR || $network >= self::NETWORK_RETRIES) {
                    throw $e;
                }
                $wait = 2 << $network;   // 2, 4, 8 s
                $network++;
                $this->log('debug', 'POST ' . $url . ' : ' . $e->getMessage() . ', nouvel essai ' . $network . '/' . self::NETWORK_RETRIES . ' dans ' . $wait . ' s');
                // Le nonce envoyé est peut-être consommé : on en redemandera un neuf.
                $this->nonce = null;
                sleep($wait);
                continue;
            }
            $this->log('debug', 'POST ' . $url . ' -> HTTP ' . $res['status']);
            if (!empty($res['headers']['replay-nonce'])) {
                $this->nonce = $res['headers']['replay-nonce'];
            }
            if ($res['status'] < 400) {
                return $res;
            }
            $problem = self::problemOf($res);
            $type = isset($problem['type']) ? $problem['type'] : '';
            if ($type === 'urn:ietf:params:acme:error:badNonce' && $badNonce < self::BAD_NONCE_RETRIES) {
                $badNonce++;
                $this->log('debug', 'Nonce refusé, nouvel essai ' . $badNonce . '/' . self::BAD_NONCE_RETRIES);
                continue;
            }
            if (($res['status'] >= 500 || $res['status'] === 429) && $server < self::SERVER_RETRIES) {
                $wait = self::retryAfter($res);
                if ($res['status'] >= 500 && $wait === 0) {
                    $wait = 2 << $server;
                }
                if ($wait > 0 && $wait <= self::MAX_RETRY_AFTER) {
                    $server++;
                    $this->log('debug', 'Autorité indisponible (HTTP ' . $res['status'] . '), nouvel essai dans ' . $wait . ' s');
                    sleep($wait);
                    continue;
                }
            }
            $this->throwProblem($res, 'Requête ACME refusée');
        }
    }

    /** Construit le JWS aplati (RFC 7515 §7.2.2). */
    private function jws(string $url, $payload, bool $useJwk): string {
        $protected = array(
            'alg' => acmeCrypto::alg($this->accountKey),
            'nonce' => $this->takeNonce(),
            'url' => $url,
        );
        if ($useJwk) {
            $protected['jwk'] = acmeCrypto::jwk($this->accountKey);
        } else {
            $this->requireAccount();
            $protected['kid'] = $this->accountUrl;
        }
        $p64 = acmeCrypto::b64url(acmeCrypto::jsonEncode($protected));
        $b64 = $payload === null ? '' : acmeCrypto::b64url(acmeCrypto::jsonEncode($payload));
        try {
            $sig = acmeCrypto::sign($this->accountKey, $p64 . '.' . $b64);
        } catch (Throwable $e) {
            throw new acmeException('Signature impossible avec la clé du compte : ' . $e->getMessage(), array(), 0, $e);
        }
        return acmeCrypto::jsonEncode(array(
            'protected' => $p64,
            'payload' => $b64,
            'signature' => acmeCrypto::b64url($sig),
        ));
    }

    /** Nonce à usage unique : celui de la dernière réponse, sinon HEAD newNonce. */
    private function takeNonce(): string {
        if ($this->nonce !== null) {
            $n = $this->nonce;
            $this->nonce = null;
            return $n;
        }
        $url = $this->getDirectory()['newNonce'];
        $res = $this->httpWithRetry('HEAD', $url);
        if (empty($res['headers']['replay-nonce'])) {
            throw new acmeException('L\'autorité n\'a pas fourni de nonce (HTTP ' . $res['status'] . ')');
        }
        return $res['headers']['replay-nonce'];
    }

    /** Requête non signée (annuaire, nonce) avec réessais sur les erreurs serveur passagères. */
    private function httpWithRetry(string $method, string $url): array {
        for ($i = 0; ; $i++) {
            try {
                $res = self::httpRaw($method, $url);
            } catch (acmeException $e) {
                if ($i >= self::SERVER_RETRIES - 1) {
                    throw $e;
                }
                $this->log('debug', $method . ' ' . $url . ' : ' . $e->getMessage() . ', nouvel essai');
                sleep(2 << $i);
                continue;
            }
            $this->log('debug', $method . ' ' . $url . ' -> HTTP ' . $res['status']);
            if ($res['status'] >= 500 && $i < self::SERVER_RETRIES - 1) {
                $wait = self::retryAfter($res);
                sleep($wait > 0 && $wait <= self::MAX_RETRY_AFTER ? $wait : (2 << $i));
                continue;
            }
            return $res;
        }
    }

    /**
     * Requête HTTP brute. Renvoie ['status' => int, 'headers' => [nom en minuscules => valeur], 'body' => string].
     * Lève une acmeException sur erreur réseau.
     */
    private static function httpRaw(string $method, string $url, ?string $body = null, array $headers = array()): array {
        if (!function_exists('curl_init')) {
            throw new acmeException('Extension PHP curl absente');
        }
        $ch = curl_init($url);
        $respHeaders = array();
        $opts = array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => self::HTTP_CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT => self::HTTP_TIMEOUT,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$respHeaders) {
                $trim = trim($line);
                if (stripos($trim, 'HTTP/') === 0) {
                    $respHeaders = array();   // nouvelle réponse (100 Continue…)
                } elseif (($pos = strpos($trim, ':')) !== false) {
                    $name = strtolower(trim(substr($trim, 0, $pos)));
                    $value = trim(substr($trim, $pos + 1));
                    // Link peut être répété (chaînes alternatives, « up »…) : on concatène.
                    $respHeaders[$name] = isset($respHeaders[$name]) ? $respHeaders[$name] . ', ' . $value : $value;
                }
                return strlen($line);
            },
        );
        if ($method === 'HEAD') {
            $opts[CURLOPT_NOBODY] = true;
        } elseif ($method === 'POST') {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = (string) $body;
        } elseif ($method !== 'GET') {
            $opts[CURLOPT_CUSTOMREQUEST] = $method;
        }
        curl_setopt_array($ch, $opts);
        $resp = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);   // sans effet (et déprécié à terme) à partir de PHP 8
        }
        if ($resp === false || $errno !== 0) {
            throw new acmeException('Erreur réseau vers ' . parse_url($url, PHP_URL_HOST) . ' : ' . $error . ' (curl ' . $errno . ')',
                array(), self::NETWORK_ERROR);
        }
        return array('status' => $status, 'headers' => $respHeaders, 'body' => (string) $resp);
    }

    /* ------------------------------------------------------------------ */
    /* Outils                                                              */
    /* ------------------------------------------------------------------ */

    /** Retry-After en secondes (entier ou date HTTP), 0 si absent, borné à MAX_RETRY_AFTER… sauf pour décider de ne pas attendre. */
    private static function retryAfter(array $res): int {
        if (empty($res['headers']['retry-after'])) {
            return 0;
        }
        $v = trim($res['headers']['retry-after']);
        if (ctype_digit($v)) {
            return (int) $v;
        }
        $t = strtotime($v);
        return $t === false ? 0 : max(0, $t - time());
    }

    /** Attend $seconds, borné par MAX_RETRY_AFTER et par l'échéance. */
    private function pause(int $seconds, int $deadline): void {
        $seconds = min($seconds, self::MAX_RETRY_AFTER, max(1, $deadline - time()));
        if ($seconds > 0) {
            sleep($seconds);
        }
    }

    private static function decodeJson(array $res, string $what): array {
        $data = json_decode($res['body'], true);
        if (!is_array($data)) {
            throw new acmeException('Réponse JSON invalide (' . $what . ', HTTP ' . $res['status'] . ')');
        }
        return $data;
    }

    private static function problemOf(array $res): array {
        $data = json_decode($res['body'], true);
        return is_array($data) ? $data : array();
    }

    /** @return never */
    private function throwProblem(array $res, string $context): void {
        $problem = self::problemOf($res);
        $msg = $context . ' (HTTP ' . $res['status'] . ')';
        if (count($problem)) {
            $msg .= ' : ' . self::describeProblem($problem);
        }
        $this->log('debug', $msg);
        throw new acmeException($msg, $problem, $res['status']);
    }

    /** Résumé lisible d'un document problème, sous-problèmes compris. */
    public static function describeProblem(array $problem): string {
        $type = isset($problem['type']) ? preg_replace('/^urn:ietf:params:acme:error:/', '', (string) $problem['type']) : '';
        $detail = isset($problem['detail']) ? (string) $problem['detail'] : '';
        $out = trim(($type !== '' ? '[' . $type . '] ' : '') . $detail);
        if (!empty($problem['subproblems']) && is_array($problem['subproblems'])) {
            $subs = array();
            foreach ($problem['subproblems'] as $sp) {
                if (!is_array($sp)) {
                    continue;
                }
                $id = isset($sp['identifier']['value']) ? $sp['identifier']['value'] . ' : ' : '';
                $subs[] = $id . self::describeProblem($sp);
            }
            if (count($subs)) {
                $out .= ' ; ' . implode(' ; ', $subs);
            }
        }
        return $out === '' ? 'erreur sans détail' : $out;
    }

    /** Erreur portée par une autorisation : celle du premier défi en échec. */
    private static function authzProblem(array $authz): array {
        foreach ((isset($authz['challenges']) ? $authz['challenges'] : array()) as $c) {
            if (!empty($c['error']) && is_array($c['error'])) {
                return $c['error'];
            }
        }
        return array();
    }

    private static function normalizeDomains(array $domains): array {
        $out = array();
        foreach ($domains as $d) {
            $d = strtolower(trim((string) $d));
            if ($d !== '' && !in_array($d, $out, true)) {
                $out[] = $d;
            }
        }
        if (count($out) === 0) {
            throw new acmeException('Aucun domaine demandé');
        }
        return $out;
    }

    /** Masque un secret pour le journal : quatre premiers caractères puis « … ». */
    public static function mask(string $secret): string {
        return strlen($secret) <= 4 ? '…' : substr($secret, 0, 4) . '…';
    }

    private function log(string $level, string $message): void {
        if ($this->logger === null) {
            return;
        }
        try {
            call_user_func($this->logger, $level, $message);
        } catch (Throwable $e) {
            // Un journal défaillant ne doit jamais interrompre une émission.
        }
    }
}

# Plugin ACME — conception et contrat entre les modules

Document de travail (non déployé). Il fixe l'architecture et **les signatures
exactes** que chaque module expose, pour que les modules restent indépendants
et testables séparément.

## 1. Objectif

Obtenir et renouveler automatiquement un certificat TLS gratuit (Let's Encrypt,
puis ZeroSSL ou toute autorité ACME) pour le Jeedom, et l'installer dans son
serveur web pour passer en HTTPS.

Cas de référence : un nom sous un domaine personnel (ex. `jeedom.example.org`),
DNS chez OVH, Jeedom en réseau local derrière un routeur dont le port 80 public
n'est pas redirigé vers Jeedom : **DNS-01 via l'API OVH** est le cas
prioritaire, HTTP-01 doit exister aussi.

## 2. Principes non négociables

1. **Aucune dépendance** : pas d'acme.sh, pas de certbot, pas de Composer.
   Seulement les extensions PHP `openssl`, `curl` et `json`, déjà exigées par le
   cœur de Jeedom.
2. **Compatibilité PHP 7.4 → 8.4** (Jeedom 4.4 sur Debian 11 tourne en 7.4).
   Donc interdits : `match`, `enum`, `readonly`, arguments nommés, types union
   (`int|string`), `mixed`, `never`, `str_contains`, `str_starts_with`,
   `str_ends_with`, promotion de propriétés dans le constructeur, `?->`. Les types
   nullables (`?string`), les types de retour scalaires et `void` sont permis.
3. **Multi-OS** : le code PHP est portable par construction. La seule partie
   dépendante du système, l'installation dans le serveur web, est isolée dans
   un script POSIX `sh` (pas de bash) qui détecte la distribution et le serveur
   web, et qui **ne casse jamais un serveur qui marche** : sauvegarde, test de
   configuration, retour arrière automatique.
4. **Bibliothèques indépendantes de Jeedom** : les classes `acmeCrypto`,
   `acmeClient`, `acmeSolver*`, `acmeDns*` et `acmeInstaller` ne dépendent
   d'aucune classe du cœur. Elles reçoivent un journal sous la forme d'un
   callable `function (string $level, string $message)` (niveaux : `debug`,
   `info`, `warning`, `error`). Elles se testent en ligne de commande hors de
   Jeedom. Seules `acme` et `acmeCmd` (fichier `acme.class.php`) connaissent
   Jeedom.
5. **Aucun secret dans les journaux** : clés privées, clés API, HMAC EAB,
   consumer key, jamais écrits en clair (masquer : `abcd…`).
6. Erreurs : toute erreur lève `acmeException` (définie dans
   `acmeClient.class.php`, `class acmeException extends Exception`, avec
   `public function getProblem(): array`, qui renvoie le document problème ACME
   ou un tableau vide). Côté Jeedom, attraper `Throwable`.
7. Style : commentaires en français, comme les autres plugins de l'auteur
   (voir `../jeedom-plugin-jeeterm`). Auteur : `sMug (Jérôme Fafchamps)`.
   Licence AGPL.

## 3. Arborescence et propriétaire de chaque fichier

| Fichier | Module |
|---|---|
| `core/class/acmeCrypto.class.php` | M1 — cœur ACME |
| `core/class/acmeClient.class.php` (+ `acmeException`) | M1 |
| `tests/test_crypto.php`, `tests/test_staging.php` | M1 |
| `core/class/acmeSolver.class.php` (abstraite + `acmeSolverHttp` + `acmeSolverDns`) | M2 — validation |
| `core/class/acmeDns.class.php` (interface + registre + `acmeDnsCheck`) | M2 |
| `core/class/acmeDnsOvh.class.php` | M2 |
| `tests/test_solvers.php`, `tests/test_ovh.php` | M2 |
| `resources/acme_webserver.sh` | M3 — installation serveur web |
| `core/class/acmeInstaller.class.php` | M3 |
| `tests/test_webserver.sh` | M3 |
| `plugin_info/*`, `core/class/acme.class.php`, `core/ajax/acme.ajax.php`, `core/php/acmeRun.php`, `core/config/acme.config.ini`, `core/i18n/en_US.json`, `desktop/php/acme.php`, `desktop/js/acme.js`, `docs/*`, `README.md`, `LICENSE`, `.gitignore`, `.deployignore`, `tests/check-classes.php`, `.htaccess` de chaque dossier | M4 — intégration Jeedom |

`acme.class.php` charge les autres par `require_once __DIR__ . '/acmeXxx.class.php'`
(l'autoload du cœur ne connaît que la classe qui porte l'`id` du plugin).

## 4. Contrats

### 4.1 `acmeCrypto` (M1) — méthodes statiques

```php
class acmeCrypto {
    // Types de clé : 'ec256' (défaut), 'ec384', 'rsa2048', 'rsa4096'
    public static function generateKey(string $type = 'ec256'): string;      // PEM
    public static function b64url(string $data): string;
    public static function b64urlDecode(string $data): string;
    public static function jwk(string $keyPem): array;        // membres publics, triés pour l'empreinte (RFC 7638)
    public static function thumbprint(string $keyPem): string; // b64url(sha256(json jwk))
    public static function alg(string $keyPem): string;        // 'ES256' | 'ES384' | 'RS256'
    public static function sign(string $keyPem, string $data): string; // signature brute JWS (EC : R||S, pas DER)
    public static function csr(string $keyPem, array $domains): string; // DER ; SAN = tous les domaines, CN = le premier
    public static function certInfo(string $certPem): array;
    //  ['notBefore' => int, 'notAfter' => int, 'domains' => string[], 'issuer' => string,
    //   'serial' => string (hex), 'daysLeft' => int]
    public static function splitChain(string $pem): array;      // liste de PEM, feuille en premier
    public static function keyMatchesCert(string $keyPem, string $certPem): bool;
}
```

CSR avec SAN en PHP : `openssl_csr_new` exige un fichier de configuration
temporaire contenant `subjectAltName` ; il doit fonctionner avec OpenSSL 1.1 et 3.x.

### 4.2 `acmeClient` (M1)

```php
class acmeClient {
    const LETSENCRYPT         = 'https://acme-v02.api.letsencrypt.org/directory';
    const LETSENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';
    const ZEROSSL             = 'https://acme.zerossl.com/v2/DV90';

    public function __construct(string $directoryUrl, string $accountKeyPem, ?callable $logger = null);
    public function getDirectory(): array;
    public function requiresEab(): bool;                     // meta.externalAccountRequired
    // Crée ou retrouve le compte (même clé = même compte). Renvoie l'URL du compte (kid).
    public function registerAccount(string $email, ?string $eabKid = null, ?string $eabHmacKey = null): string;
    public function setAccountUrl(string $url): void;        // évite un appel si déjà connu
    // Émission complète. $solver est un acmeSolver (4.3). Renvoie :
    //  ['fullchain' => PEM, 'cert' => PEM feuille, 'chain' => PEM intermédiaires, 'url' => URL du certificat]
    public function issue(array $domains, string $certKeyPem, acmeSolver $solver): array;
    public function revoke(string $certPem, int $reason = 0): void;
    // ZeroSSL : obtient des identifiants EAB à partir d'une simple adresse e-mail
    // (POST https://api.zerossl.com/acme/eab-credentials-email, champ email).
    public static function zerosslEab(string $email): array;  // ['kid' => ..., 'hmac' => ...]
}
```

Exigences : nonce (`HEAD newNonce`, puis en-tête `Replay-Nonce`), nouvel essai
sur `badNonce`, `Retry-After` respecté, POST-as-GET, User-Agent
`jeedom-acme/<version>`, délais d'attente maximaux bornés (ordre : 3 min).
Dans `issue()`, pour chaque autorisation `pending`, choisir le défi dont le type
vaut `$solver->getType()`, puis :
`keyAuthorization = token . '.' . thumbprint(accountKey)`.
Déroulé : `prepare()` pour toutes les autorisations → `waitReady()` une fois →
répondre aux défis → interroger les autorisations → **`cleanup()` toujours,
dans un `finally`** → finalisation par CSR → attente de `valid` → téléchargement.
Une autorisation déjà `valid` (réutilisée par l'autorité) est sautée.

### 4.3 Solveurs (M2) — `acmeSolver.class.php`

```php
abstract class acmeSolver {
    public function setLogger(?callable $logger): void;
    abstract public function getType(): string;             // 'http-01' | 'dns-01'
    // $domain sans le préfixe '*.' (l'identifiant ACME d'un wildcard est déjà sans « *. »).
    abstract public function prepare(string $domain, string $token, string $keyAuthorization): void;
    public function waitReady(): void {}                     // attend que tout soit visible de l'extérieur
    abstract public function cleanup(): void;                // retire tout ce qui a été posé, sans lever
}

class acmeSolverHttp extends acmeSolver {
    public function __construct(string $webroot);            // ex. '/var/www/html'
    // écrit <webroot>/.well-known/acme-challenge/<token> contenant keyAuthorization
}

class acmeSolverDns extends acmeSolver {
    // options : 'propagationTimeout' (s, défaut 300), 'pollInterval' (s, défaut 10),
    //           'checkPropagation' (bool, défaut true), 'extraDelay' (s, défaut 0),
    //           'stateFile' (chemin JSON des TXT posés par le plugin et pas encore
    //           retirés : seuls ceux-là sont nettoyés, jamais un TXT d'un autre outil)
    public function __construct(acmeDnsProvider $provider, array $options = array());
    // TXT '_acme-challenge.<domain>' = b64url(sha256(keyAuthorization))
}
```

### 4.4 DNS (M2) — `acmeDns.class.php` et `acmeDnsOvh.class.php`

```php
interface acmeDnsProvider {
    public function __construct(array $config, ?callable $logger = null);
    public static function getLabel(): string;                // 'OVHcloud'
    // Champs affichés par l'interface : clé => ['label' => ..., 'type' => 'text'|'password'|'select',
    //  'options' => [valeur => libellé] (select), 'default' => ..., 'help' => ...]
    public static function getFields(): array;
    public function test(): string;                           // vérifie les accès, renvoie un résumé lisible, lève sinon
    public function addTxt(string $fqdn, string $value): void;
    public function removeTxt(string $fqdn, string $value): void;
    public function commit(): void;                           // ex. OVH : POST /domain/zone/{zone}/refresh
}

class acmeDns {
    public static function providers(): array;                // ['ovh' => 'acmeDnsOvh']
    public static function create(string $id, array $config, ?callable $logger = null): acmeDnsProvider;
}

class acmeDnsCheck {
    // Vrai quand TOUS les serveurs faisant autorité pour la zone renvoient la valeur.
    // Implémentation sans dépendance : requête DNS brute en UDP (et TCP en repli),
    // serveurs d'autorité trouvés via dns_get_record(NS), repli DoH
    // (https://cloudflare-dns.com/dns-query, https://dns.google/resolve) si l'UDP 53 sortant est bloqué.
    public static function txtVisible(string $fqdn, string $value, ?callable $logger = null): bool;
}
```

OVH : points d'accès `ovh-eu`, `ovh-ca`, `ovh-us`, `kimsufi-eu`, `kimsufi-ca`,
`soyoustart-eu`, `soyoustart-ca`. Champs : `endpoint`, `application_key`,
`application_secret`, `consumer_key`. Signature
`"$1$" . sha1(AS + "+" + CK + "+" + METHOD + "+" + URL + "+" + BODY + "+" + TSTAMP)`,
décalage horaire via `GET /auth/time`. Zone trouvée par le plus long suffixe
parmi `GET /domain/zone`. Méthode statique supplémentaire :
`acmeDnsOvh::createTokenUrl(string $endpoint): string` renvoie l'URL de création
d'un jeton limité à `GET/POST/DELETE /domain/zone/*`.

### 4.5 Installation dans le serveur web (M3)

Script `resources/acme_webserver.sh`, POSIX, exécuté **en root** (via
`sudo` quand il est disponible). Actions :

```
acme_webserver.sh detect
acme_webserver.sh install --domain D --fullchain F --key K [--alias NOM]... [--port 443] [--redirect 0|1] [--webroot /var/www/html] [--force-port]
acme_webserver.sh reload
acme_webserver.sh uninstall
acme_webserver.sh status
```

Sortie : lignes `cle=valeur` sur stdout (analysables), messages lisibles sur
stderr, code retour 0 si succès. `detect` produit au moins : `os_id`,
`os_version`, `webserver` (`apache`|`nginx`|`unknown`), `layout`
(`debian`|`rhel`|`suse`|`alpine`|`arch`|`generic`), `docker` (0|1),
`systemd` (0|1), `ssl_module` (0|1), `supported` (0|1), `reason`.

Règles : certificats copiés dans `/etc/ssl/jeedom-acme/` (clé en 0600), jamais
référencés directement dans le dossier du plugin (désinstaller le plugin ne doit
pas empêcher Apache de démarrer). Toute configuration écrite porte un
commentaire « géré par le plugin Jeedom acme ». Avant chaque changement :
sauvegarde, puis test de configuration (`apachectl -t` / `nginx -t`), puis
rechargement en douceur (graceful). Si le test échoue : restauration et code de
retour ≠ 0. La redirection 80 → 443 laisse toujours passer `/.well-known/acme-challenge/`.
Variable d'environnement `ACME_ROOT` (préfixe de chemins, défaut vide) et
`ACME_DRYRUN=1` pour tester sans toucher au système.

```php
class acmeInstaller {
    public function __construct(?callable $logger = null, string $sudo = 'sudo ');   // Jeedom passe system::getCmdSudo()
    public function detect(): array;              // tableau des clés de `detect`
    public function install(string $domain, string $fullchainPem, string $keyPem, array $options = array()): array;
    //   options : 'port' => 443, 'redirect' => false, 'webroot' => '/var/www/html',
    //             'aliases' => string[] (tous les noms du certificat ; défaut : SAN du certificat),
    //             'force_port' => false
    //   codes du script : 10 port occupé (autre programme ou vhost HTTP), 11 Apache
    //   arrêté après rechargement (état restauré, Apache relancé), 12 port impossible
    //   à vérifier sans ss/netstat (refus sauf --force-port) ; voir l'en-tête du script
    //   écrit les PEM dans un fichier temporaire 0600, appelle le script, renvoie
    //   ['ok' => bool, 'output' => string, 'data' => array cle=>valeur]
    public function reload(): array;
    public function uninstall(): array;
    public function status(): array;
}
```

### 4.6 Intégration Jeedom (M4)

Un **équipement = un certificat**. Clés de configuration de l'eqLogic :

| Clé | Valeurs |
|---|---|
| `domains` | liste séparée par virgules / retours à la ligne ; le premier est le nom principal |
| `ca` | `letsencrypt` (défaut), `letsencrypt_staging`, `zerossl`, `custom` |
| `directory_url` | si `ca = custom` |
| `email` | contact ACME (obligatoire pour ZeroSSL) |
| `eab_kid`, `eab_hmac` | si l'autorité exige l'EAB (ZeroSSL : rempli automatiquement via `zerosslEab()`) |
| `challenge` | `dns-01` (défaut) ou `http-01` |
| `webroot` | pour http-01, défaut : racine de Jeedom |
| `dns_provider` | `ovh` |
| `dns_<champ>` | un par champ de `getFields()` du fournisseur |
| `dns_propagation_timeout` | secondes, défaut 300 |
| `key_type` | `ec256` (défaut), `ec384`, `rsa2048`, `rsa4096` |
| `install_webserver` | 0/1 : installer dans le serveur web local |
| `https_port` | défaut 443 |
| `redirect_https` | 0/1 |
| `renew_before_days` | vide = automatique (un tiers de la durée de vie restante) |

Commandes info (logicalId) : `status` (`none`, `valid`, `renew_soon`, `expired`,
`error`), `expiration` (date lisible), `days_left` (numérique, unité « j »),
`issuer`, `last_renewal`, `last_error`. Commandes action : `renew` (forcer),
`install` (réinstaller dans le serveur web).

Stockage : `data/accounts/<sha1(directoryUrl)>/account.key` + `account.json`
(URL du compte), `data/certs/<eqLogicId>/privkey.pem`, `cert.pem`,
`chain.pem`, `fullchain.pem`, `meta.json`. Dossiers en 0700, fichiers en 0600,
`data/.htaccess` qui refuse tout. `.deployignore` contient `data/` et `tests/` :
sinon `deploy-plugin.sh --delete` effacerait les clés à chaque déploiement.

Une émission peut durer plusieurs minutes (propagation DNS). Elle tourne donc en
**tâche de fond** : l'ajax lance `php core/php/acmeRun.php id=<eqId> action=issue|renew|install [force=1]`
détaché (`nohup … &`), la tâche écrit son avancement dans le journal `acme` et
dans le cache de l'équipement (`acme::job` : état, étape, horodatage) ; la page
interroge l'ajax `jobStatus`. Un verrou par équipement empêche deux tâches
simultanées.

`cronDaily` : met à jour les commandes de chaque équipement actif, renouvelle
ce qui arrive à échéance, et crée un `message::add` si l'échéance approche
(moins de 14 jours) alors que le renouvellement échoue. Let's Encrypt n'envoie
plus d'e-mails d'expiration depuis 2025 : c'est le plugin qui prévient.

`acme_remove()` (désinstallation) : ne supprime pas la configuration du serveur
web (sinon on coupe l'accès à Jeedom en HTTPS sans prévenir) ; la documentation
explique comment le faire via le bouton « Désinstaller du serveur web ».

## 5. Compatibilité visée (à reporter dans la documentation)

| Plateforme | Émission (DNS-01 / HTTP-01) | Installation auto HTTPS |
|---|---|---|
| Debian / Raspberry Pi OS / Ubuntu + Apache (installation Jeedom officielle, Smart, Luna, Atlas) | oui | oui |
| Docker (image officielle Jeedom, Apache) | oui | oui (sans systemd : `apachectl -k graceful`), à condition de publier le port 443 |
| RHEL / Fedora / Alma / Rocky + Apache | oui | oui si `mod_ssl` est installé |
| Alpine + Apache | oui | oui si `apache2-ssl` est installé |
| nginx | oui | semi-automatique : fichier de configuration généré, inclusion à faire à la main |
| Autre / sans droits root | oui | non : les fichiers PEM sont téléchargeables et utilisables ailleurs (proxy inverse, NAS…) |

## 6. Rappels réseau (à reporter dans la documentation)

- **HTTP-01** : l'autorité se connecte **toujours au port 80** de l'IP publique
  du nom. Elle suit les redirections, mais seulement vers les ports 80 et 443.
  Une redirection du routeur « port public 9002 → Jeedom » ne suffit donc pas :
  il faut « port public 80 → Jeedom:80 ».
- **DNS-01** : aucun port à ouvrir. Marche pour un Jeedom purement local, et
  permet les wildcards. C'est le mode par défaut.

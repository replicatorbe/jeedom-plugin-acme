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
 * Intégration Jeedom du plugin ACME : un équipement = un certificat.
 *
 * Ce fichier est le seul du plugin à connaître Jeedom. Le protocole ACME, les
 * solveurs, les fournisseurs DNS et l'installation dans le serveur web sont
 * des bibliothèques indépendantes (voir CONCEPTION.md) : on leur passe un
 * journal sous la forme d'une fonction, et on attrape Throwable autour de
 * chaque appel.
 *
 * L'autoload du coeur ne connaît que la classe qui porte l'identifiant du
 * plugin : les autres fichiers sont chargés ici, explicitement.
 */

/* Le coeur est déjà chargé dans tous les cas réels ; la condition permet à
 * tests/check-classes.php de charger ce fichier depuis le dépôt, hors de
 * l'arborescence de Jeedom. */
if (!function_exists('include_file')) {
    require_once __DIR__ . '/../../../../core/php/core.inc.php';
}
require_once __DIR__ . '/acmeCrypto.class.php';
require_once __DIR__ . '/acmeClient.class.php';
require_once __DIR__ . '/acmeSolver.class.php';
require_once __DIR__ . '/acmeDns.class.php';
require_once __DIR__ . '/acmeDnsOvh.class.php';
require_once __DIR__ . '/acmeInstaller.class.php';

class acme extends eqLogic {

    /* Aucune propriété ici sans souligné initial : DB::save() prendrait toute
     * autre propriété pour une colonne de la table eqLogic. */

    /* Une tâche « en cours de lancement » dont le processus n'a pas pris le
     * verrou au bout de ce délai est considérée comme morte-née. */
    const JOB_START_TIMEOUT = 60;

    /* Nombre de lignes de journal gardées dans l'état de la tâche, pour la page. */
    const JOB_LINES = 40;

    /* Clé du cache de l'équipement qui porte l'état de la tâche de fond. */
    const JOB_CACHE_KEY = 'acme::job';

    /* Suffixes qu'aucune autorité publique ne certifiera jamais : réseau local,
     * noms réservés par la RFC 2606 / 6761. Refusés tout de suite, avec une
     * explication, plutôt qu'après un aller-retour chez l'autorité. */
    const PRIVATE_SUFFIXES = array('local', 'lan', 'home', 'internal', 'localdomain', 'localhost',
                                   'intranet', 'corp', 'private', 'test', 'invalid', 'example', 'arpa');

    /* Valeur affichée à la place d'un secret pour qui n'est pas administrateur. */
    const SECRET_MASK = '********';

    /* ============================================================== SÉCURITÉ */

    /*
     * Vrai si le contexte courant peut voir les secrets et déclencher des
     * émissions : ligne de commande (cron, scénarios, tâche de fond), ou
     * utilisateur administrateur, connecté par session ou par l'API JSON-RPC
     * avec sa clé personnelle.
     *
     * Tout autre contexte web est refusé, y compris un appel à l'API sans
     * utilisateur (clé API d'un plugin) : impossible d'y distinguer un
     * administrateur, et rien n'y a besoin des secrets.
     */
    public static function isPrivilegedContext(): bool {
        if (php_sapi_name() === 'cli') {
            return true;
        }
        global $_USER_GLOBAL;
        if (isset($_USER_GLOBAL) && is_object($_USER_GLOBAL)) {
            return $_USER_GLOBAL->getProfils() === 'admin';
        }
        try {
            return isConnect('admin');
        } catch (Throwable $e) {
            return false;
        }
    }

    /* Clés de configuration qui portent un secret : les champs « password » de
     * tous les fournisseurs DNS connus (pas seulement celui choisi : une valeur
     * saisie reste enregistrée si l'on change de fournisseur), et la clé HMAC
     * EAB. */
    public static function secretKeys(): array {
        $keys = array('eab_hmac');
        try {
            foreach (acmeDns::providers() as $class) {
                if (!class_exists($class)) {
                    continue;
                }
                foreach ($class::getFields() as $key => $field) {
                    if (isset($field['type']) && $field['type'] === 'password') {
                        $keys[] = 'dns_' . $key;
                    }
                }
            }
        } catch (Throwable $e) {
            /* Au pire, seule la clé EAB est masquée : on ne bloque rien. */
        }
        return array_values(array_unique($keys));
    }

    /*
     * Représentation de l'équipement renvoyée par le coeur (eqLogic.ajax.php
     * byId / listByType, API JSON-RPC, export…) via utils::o2a(). Même
     * signature que eqLogic::toArray(). Hors administrateur, les secrets sont
     * remplacés par un masque ; l'administrateur les reçoit tels quels, car la
     * page de l'équipement recharge son formulaire à partir de ce tableau.
     */
    public function toArray() {
        $return = parent::toArray();
        if (self::isPrivilegedContext() || !isset($return['configuration']) || !is_array($return['configuration'])) {
            return $return;
        }
        foreach (self::secretKeys() as $key) {
            if (isset($return['configuration'][$key]) && (string) $return['configuration'][$key] !== '') {
                $return['configuration'][$key] = self::SECRET_MASK;
            }
        }
        return $return;
    }

    /*
     * Appelée par DB::save() juste avant chaque écriture, y compris par
     * save(true) qui saute preSave() (setOrder, remplacement d'équipement…) :
     * c'est le seul point de passage garanti. Aucun chiffrement ici : si un
     * tableau masqué par toArray() revient à l'enregistrement, le masque ne
     * doit jamais écraser le vrai secret, on remet donc la valeur enregistrée.
     */
    public function encrypt(): void {
        $masked = array();
        foreach (self::secretKeys() as $key) {
            if ((string) $this->getConfiguration($key, '') === self::SECRET_MASK) {
                $masked[] = $key;
            }
        }
        if (count($masked) === 0) {
            return;
        }
        $saved = ($this->getId() != '') ? self::byId($this->getId()) : null;
        foreach ($masked as $key) {
            $old = is_object($saved) ? (string) $saved->getConfiguration($key, '') : '';
            $this->setConfiguration($key, ($old === self::SECRET_MASK) ? '' : $old);
        }
    }

    /* ================================================================ CHEMINS */

    /* Racine de Jeedom, par défaut racine web du défi HTTP-01. */
    public static function jeedomRoot(): string {
        $root = realpath(__DIR__ . '/../../../..');
        return ($root === false) ? '/var/www/html' : $root;
    }

    /* Dossier des données produites à l'exécution : clés et certificats. Il est
     * exclu du dépôt comme du déploiement (.gitignore, .deployignore), et donc
     * créé ici, avec ses droits et son .htaccess, s'il n'existe pas encore. */
    public static function dataDir(): string {
        $dir = dirname(__DIR__, 2) . '/data';
        self::ensureDir($dir);
        $htaccess = $dir . '/.htaccess';
        if (!is_file($htaccess)) {
            /* Les deux syntaxes : Apache 2.4 (Require) et l'ancienne (Deny). */
            $content = "# Clés privées du plugin acme : aucun accès web.\n"
                     . "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
                     . "<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n";
            if (@file_put_contents($htaccess, $content) !== false) {
                @chmod($htaccess, 0644);
            }
        }
        return $dir;
    }

    /* Crée un dossier en 0700 (et ses parents), et resserre ses droits s'il
     * existait déjà avec des droits plus larges. */
    public static function ensureDir(string $dir): void {
        if (!is_dir($dir)) {
            $old = umask(0077);
            $ok = @mkdir($dir, 0700, true);
            umask($old);
            if (!$ok && !is_dir($dir)) {
                throw new Exception(__('Impossible de créer le dossier', __FILE__) . ' ' . $dir);
            }
        }
        @chmod($dir, 0700);
    }

    /*
     * Remet les droits de data/ : dossiers 0700, fichiers 0600, .htaccess
     * 0644. Le coeur fait un « chmod 775 -R » sur tout le plugin (mise à jour,
     * update::postInstallUpdate ; jeedom::cleanFileSystemRight) : sans ce
     * rattrapage, les clés privées deviendraient lisibles par le groupe.
     */
    public static function fixDataRights(): void {
        $dir = self::dataDir();
        @chmod($dir, 0700);
        self::fixRightsTree($dir);
    }

    private static function fixRightsTree(string $dir): void {
        $entries = @scandir($dir);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (is_link($path)) {
                continue;
            }
            if (is_dir($path)) {
                @chmod($path, 0700);
                self::fixRightsTree($path);
            } else {
                @chmod($path, ($entry === '.htaccess') ? 0644 : 0600);
            }
        }
    }

    /* Compte ACME : un par annuaire, partagé par tous les équipements qui
     * utilisent la même autorité. */
    public static function accountDir(string $directoryUrl): string {
        $dir = self::dataDir() . '/accounts/' . sha1($directoryUrl);
        self::ensureDir(dirname($dir));
        self::ensureDir($dir);
        return $dir;
    }

    /* Certificat de l'équipement ; les essais sur le staging vont dans un
     * sous-dossier, pour ne jamais écraser le vrai certificat. */
    public function certDir(bool $staging = false): string {
        if ($this->getId() == '') {
            throw new Exception(__('Enregistrez l\'équipement avant cette action.', __FILE__));
        }
        $dir = self::dataDir() . '/certs/' . intval($this->getId());
        if ($staging) {
            $dir .= '/staging';
        }
        self::ensureDir(dirname($dir));
        self::ensureDir($dir);
        return $dir;
    }

    /* ======================================================= FICHIERS SECRETS */

    /* Écriture atomique en 0600 : fichier temporaire créé sous umask 077 dans
     * le même dossier, puis renommé. Un lecteur ne voit jamais un PEM tronqué. */
    private static function writeSecret(string $file, string $content): void {
        $tmp = $file . '.tmp' . getmypid();
        $old = umask(0077);
        $written = @file_put_contents($tmp, $content, LOCK_EX);
        umask($old);
        if ($written === false || $written !== strlen($content)) {
            @unlink($tmp);
            throw new Exception(__('Impossible d\'écrire le fichier', __FILE__) . ' ' . $file);
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new Exception(__('Impossible d\'écrire le fichier', __FILE__) . ' ' . $file);
        }
    }

    private static function readJson(string $file): array {
        if (!is_file($file)) {
            return array();
        }
        $data = json_decode((string) @file_get_contents($file), true);
        return is_array($data) ? $data : array();
    }

    private static function writeJson(string $file, array $data): void {
        self::writeSecret($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    }

    /* État du renouvellement, tenu hors de la configuration de l'équipement :
     * la tâche de fond n'a ainsi jamais à réenregistrer l'équipement, ce qui
     * écraserait une saisie faite pendant ce temps sur la page. */
    public function readState(): array {
        $state = self::readJson($this->certDir() . '/state.json');
        return array_merge(array('last_renewal' => 0, 'last_attempt' => 0, 'last_error' => '',
                                 'install_error' => '', 'installed_at' => 0, 'installed_serial' => '',
                                 'installed_mode' => ''), $state);
    }

    private function writeState(array $changes): void {
        self::writeJson($this->certDir() . '/state.json', array_merge($this->readState(), $changes));
    }

    /* Méta du certificat en place (meta.json), ou tableau vide. */
    private function readMeta(): array {
        return self::readJson($this->certDir() . '/meta.json');
    }

    /*
     * Message du centre de messages de Jeedom, un par sujet ($kind : expiry,
     * renew, install) et par équipement. message::add() ne remplace pas le
     * texte d'un message existant de même logicalId : on retire donc l'ancien
     * d'abord, pour que le message affiché soit toujours le dernier.
     */
    private function postMessage(string $kind, string $text): void {
        $logicalId = $kind . '::' . $this->getId();
        message::removeAll('acme', $logicalId);
        message::add('acme', $this->getHumanName() . ' : ' . $text, '', $logicalId);
    }

    /* ========================================================= NOTIFICATIONS */

    /*
     * Événements auxquels une action de notification peut s'abonner. Le centre
     * de messages de Jeedom ne suffit pas : personne ne le regarde tous les
     * jours, et Let's Encrypt n'envoie plus d'e-mail d'expiration. Les actions
     * (mail, Telegram, SMS, scénario…) sont choisies par l'utilisateur sur
     * l'onglet Notifications de l'équipement.
     */
    public static function notifyEvents(): array {
        return array(
            'expiry' => __('Expiration proche', __FILE__),
            'renew_error' => __('Échec d\'obtention ou de renouvellement', __FILE__),
            'install_error' => __('Échec d\'installation dans le serveur web', __FILE__),
            'renew_ok' => __('Certificat obtenu ou renouvelé', __FILE__),
        );
    }

    /* Événements cochés par défaut sur une nouvelle action : les problèmes. */
    public static function notifyDefaultEvents(): array {
        return array('expiry' => 1, 'renew_error' => 1, 'install_error' => 1, 'renew_ok' => 0);
    }

    /* Actions enregistrées, nettoyées : jamais autre chose qu'une liste. */
    public function getNotifyActions(): array {
        $actions = $this->getConfiguration('notify_actions', array());
        if (is_string($actions)) {
            $actions = is_json($actions) ? json_decode($actions, true) : array();
        }
        return is_array($actions) ? array_values(array_filter($actions, 'is_array')) : array();
    }

    /* Traduit « #[Objet][Équipement][Commande]# » en identifiant, avec la
     * fonction du coeur qu'applique aussi scenarioExpression. Les dièses sont
     * remis quand ils manquent : cmd::humanReadableToCmd ne reconnaît un nom
     * lisible qu'entre dièses. */
    private static function notifyActionCmdId(array $action): int {
        $name = trim(isset($action['cmd']) ? (string) $action['cmd'] : '');
        if ($name === '') {
            return 0;
        }
        if (substr($name, 0, 1) === '[' && substr($name, -1) === ']') {
            $name = '#' . $name . '#';
        }
        try {
            $raw = str_replace('#', '', jeedom::fromHumanReadable($name));
        } catch (Throwable $e) {
            /* Appelé depuis preSave, qui ne doit jamais lever. */
            return 0;
        }
        return is_numeric($raw) ? intval($raw) : 0;
    }

    /*
     * Exécute les actions abonnées à $event. $event = 'test' exécute toutes
     * les actions, quel que soit leur abonnement (bouton « Tester »).
     *
     * Étiquettes remplacées dans toutes les options (titre, message…) :
     * #equipement#, #domaines#, #jours#, #expiration#, #evenement#, #message#.
     * Un titre ou un message laissé vide reçoit un texte par défaut, pour
     * qu'une action « mail » choisie sans rien remplir soit déjà utile.
     *
     * Une commande est exécutée par execCmd(), qui lève en cas d'échec : une
     * notification perdue doit au moins se voir dans le journal. Vérifié dans
     * le coeur, scenarioExpression::createAndExec avale toute erreur hors
     * scénario ; il ne sert qu'aux blocs qui ne sont pas des commandes
     * (scénario, variable…). Ne lève jamais : renvoie un compte rendu par action.
     */
    public function notify(string $event, string $text): array {
        $report = array();
        $events = self::notifyEvents();
        $label = isset($events[$event]) ? $events[$event] : __('Essai de notification', __FILE__);
        $info = array('daysLeft' => '', 'expiration' => '');
        try {
            $info = $this->getCertificateInfo();
        } catch (Throwable $e) {
            /* Pas de certificat lisible : les étiquettes restent vides. */
        }
        $domains = implode(', ', $this->getDomains());
        $tags = array(
            '#equipement#' => $this->getName(),
            '#domaines#' => $domains,
            '#jours#' => (string) $info['daysLeft'],
            '#expiration#' => (string) $info['expiration'],
            '#evenement#' => $label,
            '#message#' => $text,
        );
        $defaultTitle = '[Jeedom] ' . __('Certificat', __FILE__) . ' ' . $domains . ' : ' . $label;
        $defaultMessage = $label . "\n" . $text;

        foreach ($this->getNotifyActions() as $action) {
            $name = trim(isset($action['cmd']) ? (string) $action['cmd'] : '');
            if ($name === '') {
                continue;
            }
            $subscribed = (isset($action['events']) && is_array($action['events'])) ? $action['events'] : self::notifyDefaultEvents();
            if ($event !== 'test' && empty($subscribed[$event])) {
                continue;
            }
            $options = (isset($action['options']) && is_array($action['options'])) ? $action['options'] : array();
            foreach ($options as $key => $value) {
                if (is_string($value)) {
                    $options[$key] = str_replace(array_keys($tags), array_values($tags), $value);
                }
            }
            try {
                $cmd = null;
                $cmdId = isset($action['cmd_id']) ? intval($action['cmd_id']) : 0;
                if ($cmdId <= 0) {
                    $cmdId = self::notifyActionCmdId($action);
                }
                if ($cmdId > 0) {
                    $cmd = cmd::byId($cmdId);
                }
                if (is_object($cmd)) {
                    if ($cmd->getType() !== 'action') {
                        throw new Exception(__('ce n\'est pas une commande action', __FILE__));
                    }
                    if ($cmd->getSubType() === 'message') {
                        if (!isset($options['title']) || trim((string) $options['title']) === '') {
                            $options['title'] = $defaultTitle;
                        }
                        if (!isset($options['message']) || trim((string) $options['message']) === '') {
                            $options['message'] = $defaultMessage;
                        }
                    }
                    $cmd->execCmd($options);
                } elseif (strpos($name, '#') === 0) {
                    throw new Exception(__('commande introuvable, choisissez-la à nouveau', __FILE__));
                } else {
                    scenarioExpression::createAndExec('action', $name, $options);
                }
                $report[] = array('cmd' => $name, 'ok' => true, 'result' => __('exécutée', __FILE__));
                log::add('acme', 'info', '[' . $this->getName() . '] ' . __('Notification', __FILE__) . ' « ' . $label . ' » → ' . $name);
            } catch (Throwable $e) {
                $report[] = array('cmd' => $name, 'ok' => false, 'result' => $e->getMessage());
                log::add('acme', 'error', '[' . $this->getName() . '] ' . __('Notification en échec', __FILE__) . ' (' . $name . ') : ' . $e->getMessage());
            }
        }
        return $report;
    }

    /* Enregistre quelques clés de configuration sur une copie FRAÎCHE de
     * l'équipement, sans passer par preSave/postSave : l'objet tenu par une
     * tâche de fond date de son lancement, et l'enregistrer tel quel écraserait
     * ce que l'utilisateur a modifié entre-temps. */
    private function saveConfigKeys(array $values): void {
        $fresh = self::byId($this->getId());
        if (!is_object($fresh)) {
            return;
        }
        foreach ($values as $key => $value) {
            $fresh->setConfiguration($key, $value);
            $this->setConfiguration($key, $value);
        }
        $fresh->save(true);
    }

    /* ========================================================= CONFIGURATION */

    /* Domaines saisis, dans l'ordre (le premier est le nom principal), en
     * minuscules et sans doublon. Séparateurs : virgules, espaces, retours à
     * la ligne, points-virgules. */
    public function getDomains(): array {
        $raw = strtolower((string) $this->getConfiguration('domains', ''));
        $domains = array();
        foreach (preg_split('/[\s,;]+/', $raw) as $domain) {
            $domain = rtrim(trim($domain), '.');
            if ($domain !== '' && !in_array($domain, $domains, true)) {
                $domains[] = $domain;
            }
        }
        return $domains;
    }

    /* Vérifie un nom avant de solliciter l'autorité : les refus de l'autorité
     * sont moins parlants, et comptent dans ses limites de taux. */
    private static function checkDomain(string $domain, string $challenge): void {
        $name = $domain;
        if (strpos($name, '*.') === 0) {
            if ($challenge !== 'dns-01') {
                throw new Exception(__('Un nom générique (wildcard) exige la validation DNS-01 :', __FILE__) . ' ' . $domain);
            }
            $name = substr($name, 2);
        }
        if (filter_var($name, FILTER_VALIDATE_IP) !== false) {
            throw new Exception(__('Une adresse IP ne peut pas être certifiée par ce plugin ; utilisez un nom de domaine :', __FILE__) . ' ' . $domain);
        }
        $label = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
        if (strlen($name) > 253 || !preg_match('/^(?:' . $label . '\.)+' . $label . '$/', $name)) {
            throw new Exception(__('Nom de domaine invalide :', __FILE__) . ' ' . $domain);
        }
        $parts = explode('.', $name);
        $tld = end($parts);
        if (ctype_digit($tld)) {
            throw new Exception(__('Nom de domaine invalide :', __FILE__) . ' ' . $domain);
        }
        if (in_array($tld, self::PRIVATE_SUFFIXES, true)) {
            throw new Exception(__('Nom privé : aucune autorité publique ne le certifiera. Il faut un nom de domaine public, par exemple jeedom.mondomaine.fr :', __FILE__) . ' ' . $domain);
        }
    }

    /* URL de l'annuaire ACME. Le bouton « Tester (staging) » force toujours le
     * staging de Let's Encrypt, quelle que soit l'autorité choisie. */
    public function getDirectoryUrl(bool $staging = false): string {
        if ($staging) {
            return acmeClient::LETSENCRYPT_STAGING;
        }
        switch ($this->getConfiguration('ca', 'letsencrypt')) {
            case 'letsencrypt_staging':
                return acmeClient::LETSENCRYPT_STAGING;
            case 'zerossl':
                return acmeClient::ZEROSSL;
            case 'custom':
                $url = trim((string) $this->getConfiguration('directory_url', ''));
                if (!preg_match('#^https://[^\s]+$#i', $url)) {
                    throw new Exception(__('Autorité personnalisée : l\'URL de l\'annuaire ACME doit commencer par https://', __FILE__));
                }
                return $url;
            default:
                return acmeClient::LETSENCRYPT;
        }
    }

    /* Adresse de contact : celle de l'équipement, sinon celle de la
     * configuration du plugin. */
    public function getContactEmail(): string {
        $email = trim((string) $this->getConfiguration('email', ''));
        if ($email === '') {
            $email = trim((string) config::byKey('email', 'acme', ''));
        }
        if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new Exception(__('Adresse e-mail de contact invalide :', __FILE__) . ' ' . $email);
        }
        return $email;
    }

    /* Configuration du fournisseur DNS, reconstituée à partir des clés
     * dns_<champ> de l'équipement, champ par champ selon getFields(). */
    public function getDnsConfig(string $providerId): array {
        $providers = acmeDns::providers();
        if (!isset($providers[$providerId])) {
            throw new Exception(__('Fournisseur DNS inconnu :', __FILE__) . ' ' . $providerId);
        }
        $class = $providers[$providerId];
        $config = array();
        foreach ($class::getFields() as $key => $field) {
            $value = (string) $this->getConfiguration('dns_' . $key, '');
            if ($value === '' && isset($field['default'])) {
                $value = (string) $field['default'];
            }
            $config[$key] = trim($value);
        }
        return $config;
    }

    /* ================================================================ JOURNAL */

    /*
     * Journal passé aux bibliothèques : function (string $level, string $message).
     * Chaque ligne va dans le journal « acme » du coeur, et, pour une tâche de
     * fond, dans l'état de la tâche que la page affiche. Les bibliothèques
     * masquent déjà leurs secrets ; rien ici n'en ajoute.
     */
    public function makeLogger(bool $job = false): callable {
        $prefix = '[' . $this->getName() . '] ';
        return function ($level, $message) use ($prefix, $job) {
            $level = strtolower((string) $level);
            if (!in_array($level, array('debug', 'info', 'warning', 'error'), true)) {
                $level = 'info';
            }
            $message = (string) $message;
            log::add('acme', $level, $prefix . $message);
            if ($job && $level !== 'debug') {
                $this->jobLog($level, $message);
            }
        };
    }

    /* ================================================================ ÉMISSION */

    /*
     * Émet (ou renouvelle) le certificat de l'équipement.
     *
     * $force   : émettre même si le certificat en place est valide et pas encore
     *            à renouveler (bouton « Renouveler maintenant », commande renew).
     * $staging : essai complet sur le staging de Let's Encrypt. Rien n'est
     *            installé, les commandes ne bougent pas, le vrai certificat
     *            n'est pas touché : seul le résultat de l'essai est gardé.
     *
     * Renvoie ['skipped' => bool, 'message' => string, 'info' => array].
     */
    public function runIssue(bool $force, bool $staging = false): array {
        $logger = $this->makeLogger(true);
        try {
            $result = $this->doIssue($force, $staging, $logger);
        } catch (Throwable $e) {
            if (!$staging) {
                $this->recordFailure($e->getMessage());
            }
            throw $e;
        }
        if ($result['skipped'] || $staging) {
            return $result;
        }

        /* Le certificat est émis et enregistré : la suite (installation) ne
         * doit pas faire passer le renouvellement pour un échec. */
        $this->writeState(array('last_renewal' => time(), 'last_attempt' => time(), 'last_error' => ''));
        message::removeAll('acme', 'expiry::' . $this->getId());
        message::removeAll('acme', 'renew::' . $this->getId());
        $this->refreshInfo();

        /* Réinstallation : si l'installation automatique est cochée, ou si le
         * certificat de cet équipement est celui que sert le serveur web
         * (installé par le bouton : installed_at n'est non nul que pour
         * l'équipement installé en dernier, voir runInstall). Le serveur web
         * sert une copie des PEM : sans réinstallation, il garderait l'ancien
         * certificat jusqu'à son expiration. */
        $state = $this->readState();
        if ($this->getConfiguration('install_webserver', 0) == 1 || intval($state['installed_at']) > 0) {
            try {
                $this->runInstall();
                $result['message'] .= ' ' . __('Installé dans le serveur web.', __FILE__);
            } catch (Throwable $e) {
                /* runInstall a déjà mémorisé install_error : l'émission, elle,
                 * a réussi, et le statut ne passe pas en erreur. */
                $error = __('Certificat obtenu, mais son installation dans le serveur web a échoué :', __FILE__) . ' ' . $e->getMessage();
                $logger('error', $error);
                $this->postMessage('install', $error);
                $this->notify('install_error', $error);
                $result['message'] .= ' ' . $error;
            }
        }
        $this->notify('renew_ok', $result['message']);
        return $result;
    }

    private function doIssue(bool $force, bool $staging, callable $logger): array {
        $challenge = ($this->getConfiguration('challenge', 'dns-01') === 'http-01') ? 'http-01' : 'dns-01';
        $domains = $this->getDomains();
        if (count($domains) == 0) {
            throw new Exception(__('Aucun domaine saisi.', __FILE__));
        }
        if (count($domains) > 100) {
            throw new Exception(__('Au plus 100 noms par certificat.', __FILE__));
        }
        foreach ($domains as $domain) {
            self::checkDomain($domain, $challenge);
        }
        $directoryUrl = $this->getDirectoryUrl($staging);

        if (!$force && !$staging) {
            $reason = $this->renewalReason();
            if ($reason === '') {
                $info = $this->getCertificateInfo();
                $message = __('Le certificat en place est valide et n\'est pas encore à renouveler (', __FILE__)
                         . $info['daysLeft'] . ' ' . __('jours restants). Utilisez « Renouveler maintenant » pour forcer.', __FILE__);
                $logger('info', $message);
                return array('skipped' => true, 'message' => $message, 'info' => $info);
            }
            $logger('info', __('Émission nécessaire :', __FILE__) . ' ' . $reason);
        }

        $logger('info', ($staging ? __('Essai sur le staging de Let\'s Encrypt pour', __FILE__) : __('Demande de certificat pour', __FILE__))
                . ' ' . implode(', ', $domains) . ' (' . $challenge . ')');

        /* Compte ACME, puis solveur, puis émission. */
        $client = $this->getClient($directoryUrl, $logger);
        $solver = $this->buildSolver($challenge, $logger);

        $keyType = $this->getConfiguration('key_type', 'ec256');
        if (!in_array($keyType, array('ec256', 'ec384', 'rsa2048', 'rsa4096'), true)) {
            $keyType = 'ec256';
        }
        $logger('info', __('Génération de la clé du certificat', __FILE__) . ' (' . $keyType . ')');
        /* Une clé neuve à chaque émission : une clé compromise ne survit pas
         * au renouvellement suivant. */
        $certKey = acmeCrypto::generateKey($keyType);

        try {
            $issued = $client->issue($domains, $certKey, $solver);
        } catch (Throwable $e) {
            /* Compte inconnu de l'autorité (base remise à zéro, URL périmée) ou
             * désactivé : on en recrée un, puis un seul nouvel essai. Toute
             * autre erreur remonte telle quelle. */
            $problem = method_exists('acmeClient', 'isAccountProblem') ? acmeClient::isAccountProblem($e) : '';
            if ($problem !== 'missing' && $problem !== 'deactivated') {
                throw $e;
            }
            $logger('warning', ($problem === 'missing'
                    ? __('L\'autorité ne connaît pas ce compte ACME : nouvel enregistrement, puis nouvel essai.', __FILE__)
                    : __('Le compte ACME est désactivé : création d\'un nouveau compte, puis nouvel essai.', __FILE__))
                . ' (' . $e->getMessage() . ')');
            $this->resetAccount($directoryUrl, $problem, $logger);
            $client = $this->getClient($directoryUrl, $logger);
            /* Solveur neuf : le premier a fait son nettoyage, mieux vaut ne pas
             * compter sur son état interne. */
            $solver = $this->buildSolver($challenge, $logger);
            $issued = $client->issue($domains, $certKey, $solver);
        }
        if (empty($issued['fullchain']) || empty($issued['cert'])) {
            throw new Exception(__('L\'autorité n\'a pas renvoyé de certificat.', __FILE__));
        }
        if (!acmeCrypto::keyMatchesCert($certKey, $issued['cert'])) {
            throw new Exception(__('Le certificat reçu ne correspond pas à la clé générée.', __FILE__));
        }
        $info = acmeCrypto::certInfo($issued['cert']);

        /* Écriture : clé d'abord, puis certificats, puis méta. Chaque fichier
         * est remplacé atomiquement. */
        $dir = $this->certDir($staging);
        self::writeSecret($dir . '/privkey.pem', $certKey);
        self::writeSecret($dir . '/cert.pem', $issued['cert']);
        self::writeSecret($dir . '/chain.pem', isset($issued['chain']) ? (string) $issued['chain'] : '');
        self::writeSecret($dir . '/fullchain.pem', $issued['fullchain']);
        self::writeJson($dir . '/meta.json', array(
            'domains' => $domains,
            'ca' => $staging ? 'letsencrypt_staging' : $this->getConfiguration('ca', 'letsencrypt'),
            'directory' => $directoryUrl,
            'staging' => ($directoryUrl === acmeClient::LETSENCRYPT_STAGING),
            'challenge' => $challenge,
            'key_type' => $keyType,
            'url' => isset($issued['url']) ? (string) $issued['url'] : '',
            'issued' => time(),
            'notBefore' => $info['notBefore'],
            'notAfter' => $info['notAfter'],
            'issuer' => $info['issuer'],
            'serial' => $info['serial'],
        ));

        $message = ($staging ? __('Essai réussi : le staging a délivré un certificat (non reconnu par les navigateurs) valable jusqu\'au', __FILE__)
                             : __('Certificat obtenu, valable jusqu\'au', __FILE__))
                 . ' ' . date('Y-m-d H:i', $info['notAfter']) . ' (' . $info['issuer'] . ').';
        $logger('info', $message);
        return array('skipped' => false, 'message' => $message, 'info' => $this->getCertificateInfo($staging));
    }

    /* Échec d'une émission réelle : mémorisé, publié dans les commandes, et
     * signalé par un message si l'échéance approche. */
    private function recordFailure(string $error): void {
        try {
            $this->writeState(array('last_attempt' => time(), 'last_error' => $error));
            $this->refreshInfo();
            $this->notify('renew_error', $error);
            $info = $this->getCertificateInfo();
            $alertDays = max(1, intval(config::byKey('alert_days', 'acme', 14)));
            if ($info['exists'] && $info['daysLeft'] <= $alertDays) {
                $this->postMessage('renew', __('le renouvellement du certificat a échoué, il expire dans', __FILE__) . ' ' . $info['daysLeft'] . ' '
                    . __('jours.', __FILE__) . ' ' . $error);
            }
        } catch (Throwable $e) {
            log::add('acme', 'error', $e->getMessage());
        }
    }

    /*
     * Client ACME avec son compte. La clé du compte est créée une fois par
     * annuaire, puis réutilisée ; l'URL du compte est mémorisée pour éviter un
     * appel à chaque émission. Un verrou protège la création : deux équipements
     * de la même autorité peuvent tourner en même temps.
     */
    private function getClient(string $directoryUrl, callable $logger): acmeClient {
        $dir = self::accountDir($directoryUrl);
        $lock = fopen($dir . '/.lock', 'c');
        if ($lock === false) {
            throw new Exception(__('Impossible de verrouiller le compte ACME.', __FILE__));
        }
        flock($lock, LOCK_EX);
        try {
            $keyFile = $dir . '/account.key';
            $jsonFile = $dir . '/account.json';
            if (!is_file($keyFile)) {
                $logger('info', __('Création de la clé du compte ACME', __FILE__));
                self::writeSecret($keyFile, acmeCrypto::generateKey('ec256'));
                /* Un account.json resté d'une clé précédente désigne un compte
                 * qui n'est pas celui de la nouvelle clé. */
                @unlink($jsonFile);
            }
            $accountKey = (string) file_get_contents($keyFile);
            $thumbprint = acmeCrypto::thumbprint($accountKey);
            $client = new acmeClient($directoryUrl, $accountKey, $logger);
            $account = self::readJson($jsonFile);
            /* L'URL mémorisée ne vaut que pour la clé qui l'a obtenue. Un
             * account.json sans empreinte (version précédente du plugin) est
             * repris tel quel et complété. */
            if (!empty($account['url']) && isset($account['thumbprint']) && $account['thumbprint'] !== $thumbprint) {
                $logger('warning', __('La clé du compte ACME a changé : nouvel enregistrement du compte.', __FILE__));
                $account = array();
            }
            if (!empty($account['url'])) {
                $client->setAccountUrl($account['url']);
                if (!isset($account['thumbprint'])) {
                    $account['thumbprint'] = $thumbprint;
                    self::writeJson($jsonFile, $account);
                }
                $this->syncAccountContact($client, $jsonFile, $account, $logger);
                return $client;
            }

            $email = $this->getContactEmail();
            $eabKid = trim((string) $this->getConfiguration('eab_kid', ''));
            $eabHmac = trim((string) $this->getConfiguration('eab_hmac', ''));
            if ($client->requiresEab() && ($eabKid === '' || $eabHmac === '')) {
                if ($directoryUrl !== acmeClient::ZEROSSL) {
                    throw new Exception(__('Cette autorité exige des identifiants EAB (Key ID et clé HMAC) : renseignez-les dans l\'équipement.', __FILE__));
                }
                if ($email === '') {
                    throw new Exception(__('ZeroSSL exige une adresse e-mail de contact.', __FILE__));
                }
                $logger('info', __('Demande des identifiants EAB à ZeroSSL pour', __FILE__) . ' ' . $email);
                $eab = acmeClient::zerosslEab($email);
                $eabKid = (string) $eab['kid'];
                $eabHmac = (string) $eab['hmac'];
                /* Mémorisés dans l'équipement : ZeroSSL en délivre de nouveaux à
                 * chaque demande, autant ne pas multiplier les comptes. */
                $this->saveConfigKeys(array('eab_kid' => $eabKid, 'eab_hmac' => $eabHmac));
            }
            $logger('info', __('Enregistrement du compte ACME', __FILE__) . ($email !== '' ? ' (' . $email . ')' : ''));
            $url = $client->registerAccount($email,
                                            ($eabKid !== '' && $client->requiresEab()) ? $eabKid : null,
                                            ($eabHmac !== '' && $client->requiresEab()) ? $eabHmac : null);
            self::writeJson($jsonFile, array(
                'url' => $url,
                'email' => $email,
                'thumbprint' => $thumbprint,
                'directory' => $directoryUrl,
                'created' => time(),
            ));
            return $client;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /* Met à jour le contact du compte si l'adresse de l'équipement (ou du
     * plugin) a changé depuis l'enregistrement. Jamais bloquant : un contact
     * périmé n'empêche pas d'émettre. Appelée sous le verrou du compte. */
    private function syncAccountContact(acmeClient $client, string $jsonFile, array $account, callable $logger): void {
        try {
            $email = $this->getContactEmail();
            $known = isset($account['email']) ? (string) $account['email'] : '';
            if ($email === $known || !method_exists($client, 'updateContact')) {
                return;
            }
            $logger('info', __('Mise à jour du contact du compte ACME :', __FILE__) . ' ' . ($email !== '' ? $email : '-'));
            $client->updateContact($email);
            $account['email'] = $email;
            self::writeJson($jsonFile, $account);
        } catch (Throwable $e) {
            $logger('warning', __('Mise à jour du contact du compte ACME impossible :', __FILE__) . ' ' . $e->getMessage());
        }
    }

    /*
     * Oublie le compte après un refus de l'autorité, sous le verrou du compte.
     * 'missing' : seul account.json est supprimé, la même clé se réenregistre
     * (et retrouve son compte s'il existe encore). 'deactivated' : un compte
     * désactivé l'est pour toujours, la clé est mise de côté (renommée, pas
     * supprimée) et getClient() en créera une neuve.
     */
    private function resetAccount(string $directoryUrl, string $problem, callable $logger): void {
        $dir = self::accountDir($directoryUrl);
        $lock = fopen($dir . '/.lock', 'c');
        if ($lock === false) {
            throw new Exception(__('Impossible de verrouiller le compte ACME.', __FILE__));
        }
        flock($lock, LOCK_EX);
        try {
            @unlink($dir . '/account.json');
            if ($problem === 'deactivated' && is_file($dir . '/account.key')) {
                $aside = $dir . '/account.key.deactivated-' . date('Ymd-His');
                if (!@rename($dir . '/account.key', $aside)) {
                    throw new Exception(__('Impossible de mettre de côté la clé du compte désactivé :', __FILE__) . ' ' . $aside);
                }
                @chmod($aside, 0600);
                $logger('info', __('Clé du compte désactivé conservée sous', __FILE__) . ' ' . basename($aside));
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function buildSolver(string $challenge, callable $logger): acmeSolver {
        if ($challenge === 'http-01') {
            $webroot = trim((string) $this->getConfiguration('webroot', ''));
            if ($webroot === '') {
                $webroot = self::jeedomRoot();
            }
            $solver = new acmeSolverHttp(rtrim($webroot, '/'));
        } else {
            $providerId = (string) $this->getConfiguration('dns_provider', 'ovh');
            $provider = acmeDns::create($providerId, $this->getDnsConfig($providerId), $logger);
            $timeout = intval($this->getConfiguration('dns_propagation_timeout', 300));
            if ($timeout < 30) {
                $timeout = 300;
            }
            $solver = new acmeSolverDns($provider, array('propagationTimeout' => $timeout));
        }
        $solver->setLogger($logger);
        return $solver;
    }

    /* ======================================================= SERVEUR WEB */

    private function getInstaller(bool $job = true): acmeInstaller {
        return new acmeInstaller($this->makeLogger($job), system::getCmdSudo());
    }

    /* Port HTTPS vu depuis Internet : celui que publie le routeur (ex. 9003 →
     * Jeedom:443). C'est la cible de la redirection HTTP → HTTPS ; vide, on
     * prend le port HTTPS local. */
    public function getPublicHttpsPort(): int {
        $local = intval($this->getConfiguration('https_port', 443));
        if ($local < 1 || $local > 65535) {
            $local = 443;
        }
        $public = intval($this->getConfiguration('public_https_port', ''));
        return ($public >= 1 && $public <= 65535 && $public != 80) ? $public : $local;
    }

    /* Installe le certificat en place dans le serveur web de Jeedom. Les PEM
     * sont copiés par le script dans /etc/ssl/jeedom-acme/ : il faut donc
     * réinstaller (et pas seulement recharger) après chaque renouvellement. */
    public function runInstall(): array {
        try {
            $result = $this->doInstall();
        } catch (Throwable $e) {
            /* Erreur d'installation tenue à part de last_error : le certificat,
             * lui, est valide, et le statut ne doit pas passer en « error ». */
            try {
                $this->writeState(array('install_error' => $e->getMessage()));
                $this->refreshInfo();
            } catch (Throwable $e2) {
                log::add('acme', 'error', '[' . $this->getName() . '] ' . $e2->getMessage());
            }
            throw $e;
        }
        $this->writeState(array('install_error' => ''));
        $this->refreshInfo();
        return $result;
    }

    /*
     * Équipements acme, autres que celui-ci, qui ont l'installation automatique
     * cochée. Le serveur web n'a qu'une configuration HTTPS gérée par le plugin
     * (jeedom-acme-ssl) : un seul certificat peut y être installé.
     */
    private function otherInstallers(): array {
        $others = array();
        foreach (self::byType('acme') as $eqLogic) {
            if ($eqLogic->getId() != $this->getId() && $eqLogic->getConfiguration('install_webserver', 0) == 1) {
                $others[] = $eqLogic;
            }
        }
        return $others;
    }

    /* Après une installation (ou un retrait), plus aucun autre équipement
     * n'est « installé » : installed_at n'est non nul que pour celui dont le
     * serveur web sert réellement le certificat. N'écrit que dans les états
     * qui existent déjà (pas de dossier créé pour rien). */
    private function clearInstalledElsewhere(): void {
        foreach (self::byType('acme') as $eqLogic) {
            if ($eqLogic->getId() == $this->getId()) {
                continue;
            }
            try {
                if (!is_file(self::dataDir() . '/certs/' . intval($eqLogic->getId()) . '/state.json')) {
                    continue;
                }
                $state = $eqLogic->readState();
                if (intval($state['installed_at']) > 0 || $state['installed_serial'] !== '') {
                    $eqLogic->writeState(array('installed_at' => 0, 'installed_serial' => '', 'installed_mode' => '', 'install_error' => ''));
                    $eqLogic->refreshInfo();
                    message::removeAll('acme', 'install::' . $eqLogic->getId());
                }
            } catch (Throwable $e) {
                log::add('acme', 'warning', '[' . $eqLogic->getName() . '] ' . $e->getMessage());
            }
        }
    }

    private function doInstall(): array {
        if ($this->getConfiguration('install_webserver', 0) != 1) {
            $others = $this->otherInstallers();
            if (count($others) > 0) {
                throw new Exception(__('Le serveur web ne peut servir qu\'un certificat, et l\'installation automatique est cochée sur', __FILE__)
                    . ' ' . $others[0]->getHumanName() . ' : ' . __('il remplacerait celui-ci à son prochain renouvellement. Décochez-la d\'abord sur cet équipement.', __FILE__));
            }
        }
        $dir = $this->certDir();
        $meta = self::readJson($dir . '/meta.json');
        if (!is_file($dir . '/fullchain.pem') || !is_file($dir . '/privkey.pem') || empty($meta['domains'])) {
            throw new Exception(__('Aucun certificat à installer : obtenez-le d\'abord.', __FILE__));
        }
        if (!empty($meta['staging'])) {
            throw new Exception(__('Un certificat du staging n\'est reconnu par aucun navigateur : il n\'est jamais installé dans le serveur web.', __FILE__));
        }
        $fullchain = (string) file_get_contents($dir . '/fullchain.pem');
        $key = (string) file_get_contents($dir . '/privkey.pem');
        $cert = is_file($dir . '/cert.pem') ? (string) file_get_contents($dir . '/cert.pem') : $fullchain;
        if (!acmeCrypto::keyMatchesCert($key, $cert)) {
            throw new Exception(__('La clé privée ne correspond pas au certificat : installation refusée.', __FILE__));
        }
        $port = intval($this->getConfiguration('https_port', 443));
        if ($port < 1 || $port > 65535) {
            $port = 443;
        }
        $logger = $this->makeLogger(true);
        $logger('info', __('Installation dans le serveur web', __FILE__) . ' (' . __('port', __FILE__) . ' ' . $port . ')');
        /* Le nom principal est transmis tel quel (« *. » compris) : le script
         * décide lui-même si le nom nu est couvert, et reçoit tous les noms du
         * certificat en alias (ServerAlias et redirection). */
        $result = $this->getInstaller()->install((string) $meta['domains'][0], $fullchain, $key, array(
            'port' => $port,
            'redirect' => ($this->getConfiguration('redirect_https', 0) == 1),
            'redirect_port' => $this->getPublicHttpsPort(),
            'webroot' => self::jeedomRoot(),
            'aliases' => array_values($meta['domains']),
        ));
        if (empty($result['ok'])) {
            throw new Exception(__('Installation dans le serveur web refusée ou en échec :', __FILE__) . ' ' . self::tail(isset($result['output']) ? $result['output'] : ''));
        }
        $mode = isset($result['data']['mode']) ? (string) $result['data']['mode'] : 'auto';
        $this->writeState(array('installed_at' => time(), 'installed_serial' => isset($meta['serial']) ? (string) $meta['serial'] : '', 'installed_mode' => $mode));
        message::removeAll('acme', 'install::' . $this->getId());
        $this->clearInstalledElsewhere();
        if ($mode === 'manual') {
            /* nginx : le fragment est écrit, mais rien n'est servi en HTTPS tant
             * que l'utilisateur ne l'a pas inclus dans son bloc server. */
            $logger('warning', __('Fichiers du certificat en place, mais l\'inclusion dans la configuration du serveur web reste à faire à la main :', __FILE__) . ' ' . self::tail(isset($result['output']) ? $result['output'] : '', 12));
        } else {
            $logger('info', __('Certificat installé : Jeedom répond en HTTPS sur le port', __FILE__) . ' ' . $port . '.');
        }
        return $result;
    }

    public function runUninstall(): array {
        $logger = $this->makeLogger(true);
        $logger('info', __('Retrait de la configuration HTTPS du serveur web', __FILE__));
        $result = $this->getInstaller()->uninstall();
        if (empty($result['ok'])) {
            throw new Exception(__('Désinstallation du serveur web en échec :', __FILE__) . ' ' . self::tail(isset($result['output']) ? $result['output'] : ''));
        }
        /* La configuration retirée est la seule du plugin, quel que soit
         * l'équipement qui l'avait installée. */
        $this->writeState(array('installed_at' => 0, 'installed_serial' => '', 'installed_mode' => '', 'install_error' => ''));
        $this->clearInstalledElsewhere();
        message::removeAll('acme', 'install::' . $this->getId());
        $this->refreshInfo();
        $logger('info', __('Configuration HTTPS retirée du serveur web.', __FILE__));
        return $result;
    }

    /* Dernières lignes d'une sortie de script, pour un message lisible. */
    private static function tail(string $output, int $lines = 6): string {
        $all = preg_split('/\r?\n/', trim($output));
        return implode(' / ', array_slice($all, -$lines));
    }

    /* ================================================================== ÉTAT */

    /*
     * Description du certificat en place (ou de l'essai sur le staging) :
     * lu dans le PEM lui-même, qui fait foi, complété par meta.json et
     * state.json.
     */
    public function getCertificateInfo(bool $staging = false): array {
        $dir = $this->certDir($staging);
        $info = array(
            'exists' => false, 'staging' => $staging, 'domains' => array(), 'issuer' => '', 'serial' => '',
            'notBefore' => 0, 'notAfter' => 0, 'daysLeft' => 0, 'expiration' => '', 'issued' => 0, 'ca' => '',
            'status' => 'none', 'renewalDue' => false, 'renewalReason' => '', 'renewalDate' => '',
        );
        if (!$staging) {
            $state = $this->readState();
            $info['last_renewal'] = $state['last_renewal'] ? date('Y-m-d H:i:s', $state['last_renewal']) : '';
            $info['last_attempt'] = $state['last_attempt'] ? date('Y-m-d H:i:s', $state['last_attempt']) : '';
            $info['last_error'] = (string) $state['last_error'];
            $info['install_error'] = (string) $state['install_error'];
            $info['installed_at'] = $state['installed_at'] ? date('Y-m-d H:i:s', $state['installed_at']) : '';
            $info['installed_mode'] = (string) $state['installed_mode'];
            /* installed : le serveur web sert CE certificat (installed_at n'est
             * non nul que pour le dernier équipement installé, et le numéro de
             * série dit si c'est bien le certificat en place, et pas le
             * précédent). installed_outdated : c'est un certificat plus ancien
             * de cet équipement, la réinstallation est à faire (le cron la
             * retente chaque jour). */
            $info['installed'] = false;
            $info['installed_outdated'] = false;
            $info['install_webserver'] = ($this->getConfiguration('install_webserver', 0) == 1);
        }
        $certFile = $dir . '/cert.pem';
        if (!is_file($certFile)) {
            if (!$staging && $info['last_error'] !== '') {
                /* Première émission en échec : rien n'est en place, mais « none »
                 * cacherait l'erreur. */
                $info['status'] = 'error';
            }
            return $info;
        }
        try {
            $cert = acmeCrypto::certInfo((string) file_get_contents($certFile));
        } catch (Throwable $e) {
            $info['status'] = 'error';
            $info['last_error'] = __('Certificat illisible :', __FILE__) . ' ' . $e->getMessage();
            return $info;
        }
        $meta = self::readJson($dir . '/meta.json');
        $info['exists'] = true;
        $info['domains'] = $cert['domains'];
        $info['issuer'] = $cert['issuer'];
        $info['serial'] = $cert['serial'];
        $info['notBefore'] = $cert['notBefore'];
        $info['notAfter'] = $cert['notAfter'];
        $info['daysLeft'] = intval($cert['daysLeft']);
        $info['expiration'] = date('Y-m-d H:i', $cert['notAfter']);
        $info['issued'] = isset($meta['issued']) ? intval($meta['issued']) : 0;
        $info['ca'] = isset($meta['ca']) ? $meta['ca'] : '';
        if ($staging) {
            $info['status'] = ($cert['notAfter'] < time()) ? 'expired' : 'valid';
            return $info;
        }
        if (intval($state['installed_at']) > 0) {
            $installedSerial = strtolower(ltrim((string) $state['installed_serial'], '0'));
            $currentSerial = strtolower(ltrim((string) $cert['serial'], '0'));
            $info['installed'] = ($installedSerial !== '' && $installedSerial === $currentSerial);
            $info['installed_outdated'] = !$info['installed'];
        }
        $info['renewalDate'] = date('Y-m-d', $this->renewalTimestamp($cert['notBefore'], $cert['notAfter']));
        $info['renewalReason'] = $this->renewalReason();
        $info['renewalDue'] = ($info['renewalReason'] !== '');
        if ($cert['notAfter'] < time()) {
            $info['status'] = 'expired';
        } elseif ($info['last_error'] !== '' && $state['last_attempt'] >= $state['last_renewal']) {
            $info['status'] = 'error';
        } elseif ($info['renewalDue']) {
            $info['status'] = 'renew_soon';
        } else {
            $info['status'] = 'valid';
        }
        return $info;
    }

    /* Date à partir de laquelle le renouvellement est dû : renew_before_days
     * jours avant l'expiration, ou, à défaut, au dernier tiers de la durée de
     * vie totale (30 jours avant la fin pour un certificat de 90 jours, comme
     * le recommande Let's Encrypt ; s'adapte aux certificats plus courts).
     * La valeur saisie est bornée à la moitié de la durée de vie : 90 jours
     * saisis pour un certificat de 90 jours (ou de 6 jours) renouvelleraient
     * sinon chaque jour, jusqu'à buter sur les limites de l'autorité. */
    private function renewalTimestamp(int $notBefore, int $notAfter): int {
        $days = trim((string) $this->getConfiguration('renew_before_days', ''));
        if ($days !== '' && ctype_digit($days) && intval($days) > 0) {
            $before = min(intval($days) * 86400, intval(max(0, $notAfter - $notBefore) / 2));
            return $notAfter - $before;
        }
        return $notAfter - intval(max(86400, ($notAfter - $notBefore) / 3));
    }

    /* Raison pour laquelle une émission s'impose, ou chaîne vide. Aucun
     * certificat n'est une raison ; mais le cron, lui, ne fait que renouveler
     * ce qui existe (la première émission est un geste de l'utilisateur). */
    private function renewalReason(): string {
        $dir = $this->certDir();
        if (!is_file($dir . '/cert.pem')) {
            return __('aucun certificat', __FILE__);
        }
        try {
            $cert = acmeCrypto::certInfo((string) file_get_contents($dir . '/cert.pem'));
        } catch (Throwable $e) {
            return __('certificat illisible', __FILE__);
        }
        $meta = self::readJson($dir . '/meta.json');
        $wanted = $this->getDomains();
        $have = $cert['domains'];
        sort($wanted);
        sort($have);
        if (count($wanted) > 0 && $wanted !== $have) {
            return __('la liste des domaines a changé', __FILE__);
        }
        try {
            if (!empty($meta['directory']) && $meta['directory'] !== $this->getDirectoryUrl(false)) {
                return __('l\'autorité a changé', __FILE__);
            }
        } catch (Throwable $e) {
            /* URL personnalisée invalide : l'émission le dira. */
        }
        if (time() >= $this->renewalTimestamp($cert['notBefore'], $cert['notAfter'])) {
            return __('échéance de renouvellement atteinte', __FILE__) . ' (' . intval($cert['daysLeft']) . ' ' . __('jours restants', __FILE__) . ')';
        }
        return '';
    }

    /* Vrai si le certificat en place (réel, pas du staging) devrait être servi
     * par le serveur web — installation automatique cochée, ou installé par le
     * bouton — et que ce n'est pas lui qui y est (numéro de série différent). */
    public function needsReinstall(): bool {
        $dir = $this->certDir();
        if (!is_file($dir . '/fullchain.pem') || !is_file($dir . '/privkey.pem')) {
            return false;
        }
        $meta = $this->readMeta();
        if (empty($meta['serial']) || !empty($meta['staging'])) {
            return false;
        }
        $state = $this->readState();
        if ($this->getConfiguration('install_webserver', 0) != 1 && intval($state['installed_at']) <= 0) {
            return false;
        }
        return (string) $state['installed_serial'] !== (string) $meta['serial'];
    }

    /* Vrai si un certificat existe et doit être renouvelé (échéance atteinte,
     * domaines ou autorité modifiés). */
    public function isRenewalDue(): bool {
        if (!is_file($this->certDir() . '/cert.pem')) {
            return false;
        }
        return $this->renewalReason() !== '';
    }

    /* Met à jour les commandes info d'après le certificat en place. */
    public function refreshInfo(): array {
        $info = $this->getCertificateInfo();
        $this->checkAndUpdateCmd('status', $info['status']);
        if ($info['exists']) {
            $this->checkAndUpdateCmd('expiration', $info['expiration']);
            $this->checkAndUpdateCmd('days_left', $info['daysLeft']);
            $this->checkAndUpdateCmd('issuer', $info['issuer']);
        }
        $this->checkAndUpdateCmd('last_renewal', isset($info['last_renewal']) ? $info['last_renewal'] : '');
        /* La commande « Dernière erreur » montre l'échec d'émission, sinon
         * l'échec d'installation : un scénario doit pouvoir voir les deux. Le
         * statut, lui, ne reflète que l'émission. */
        $error = isset($info['last_error']) ? (string) $info['last_error'] : '';
        if ($error === '' && !empty($info['install_error'])) {
            $error = __('Installation dans le serveur web :', __FILE__) . ' ' . $info['install_error'];
        }
        $this->checkAndUpdateCmd('last_error', $error);
        return $info;
    }

    /* ======================================================= TÂCHE DE FOND */

    private function lockFile(): string {
        return jeedom::getTmpFolder('acme') . '/job_' . intval($this->getId()) . '.lock';
    }

    /* Vrai si le processus d'une tâche tient le verrou. Le verrou est un flock :
     * le noyau le libère à la mort du processus, il ne peut donc pas rester
     * orphelin. */
    private function lockHeld(): bool {
        $fp = @fopen($this->lockFile(), 'c');
        if ($fp === false) {
            return false;
        }
        $free = flock($fp, LOCK_EX | LOCK_NB);
        if ($free) {
            flock($fp, LOCK_UN);
        }
        fclose($fp);
        return !$free;
    }

    private function readJob(): array {
        $job = $this->getCache(self::JOB_CACHE_KEY, array());
        return is_array($job) ? $job : array();
    }

    private function writeJob(array $changes): void {
        $job = array_merge($this->readJob(), $changes, array('updated' => time()));
        $this->setCache(self::JOB_CACHE_KEY, $job);
    }

    private function jobLog(string $level, string $message): void {
        $job = $this->readJob();
        $lines = (isset($job['lines']) && is_array($job['lines'])) ? $job['lines'] : array();
        $lines[] = array('t' => date('H:i:s'), 'l' => $level, 'm' => $message);
        if (count($lines) > self::JOB_LINES) {
            $lines = array_slice($lines, -self::JOB_LINES);
        }
        $changes = array('lines' => $lines);
        if ($level === 'info') {
            $changes['step'] = $message;
        }
        $this->writeJob($changes);
    }

    /*
     * État de la tâche de fond, pour la page : state (idle, starting, running,
     * success, error), action, step, lines, result, started, finished.
     * Une tâche annoncée en cours dont le processus a disparu (verrou libre)
     * est requalifiée en erreur : la page ne tourne jamais dans le vide.
     */
    public function getJobStatus(): array {
        $job = $this->readJob();
        $state = isset($job['state']) ? $job['state'] : 'idle';
        $active = in_array($state, array('starting', 'running'), true);
        if ($active && !$this->lockHeld()) {
            /* La tâche a pu finir entre la lecture ci-dessus et le test du
             * verrou : elle écrit son résultat AVANT de rendre le verrou. On
             * relit donc l'état, et on ne requalifie que s'il annonce encore une
             * tâche en cours — sinon on écraserait un succès. */
            $job = $this->readJob();
            $state = isset($job['state']) ? $job['state'] : 'idle';
            $active = in_array($state, array('starting', 'running'), true);
            $started = isset($job['started']) ? intval($job['started']) : 0;
            if ($active && ($state === 'running' || time() - $started > self::JOB_START_TIMEOUT)) {
                $this->writeJob(array('state' => 'error', 'finished' => time(),
                                      'result' => __('La tâche s\'est arrêtée sans rendre compte : consultez le journal acme.', __FILE__)));
                $job = $this->readJob();
                $active = false;
            }
        }
        $job['state'] = isset($job['state']) ? $job['state'] : 'idle';
        $job['running'] = $active;
        return $job;
    }

    public function isJobRunning(): bool {
        $job = $this->getJobStatus();
        return !empty($job['running']);
    }

    /*
     * Lance une tâche dans un processus PHP détaché :
     *   php core/php/acmeRun.php id=<id> action=<action> [force=1] [delay=<s>] [origin=cron]
     * La requête ajax (ou le cron) rend la main aussitôt ; la tâche écrit son
     * avancement dans l'état de la tâche et dans le journal acme.
     */
    public function launchJob(string $action, array $args = array()): void {
        if (!in_array($action, array('issue', 'staging', 'renew', 'install', 'uninstall'), true)) {
            throw new Exception(__('Action inconnue :', __FILE__) . ' ' . $action);
        }
        if ($this->getId() == '') {
            throw new Exception(__('Enregistrez l\'équipement avant cette action.', __FILE__));
        }
        if ($this->isJobRunning()) {
            throw new Exception(__('Une tâche est déjà en cours pour ce certificat.', __FILE__));
        }
        $argv = array('id=' . intval($this->getId()), 'action=' . $action);
        if (!empty($args['force'])) {
            $argv[] = 'force=1';
        }
        if (!empty($args['delay'])) {
            $argv[] = 'delay=' . max(0, min(7200, intval($args['delay'])));
        }
        if (!empty($args['origin']) && preg_match('/^[a-z]+$/', $args['origin'])) {
            $argv[] = 'origin=' . $args['origin'];
        }
        $this->setCache(self::JOB_CACHE_KEY, array(
            'state' => 'starting', 'action' => $action, 'step' => __('Lancement de la tâche…', __FILE__),
            'lines' => array(), 'result' => '', 'started' => time(), 'updated' => time(), 'finished' => 0,
            'origin' => isset($args['origin']) ? (string) $args['origin'] : 'user',
        ));
        $script = realpath(__DIR__ . '/../php/acmeRun.php');
        if ($script === false) {
            throw new Exception(__('Script de tâche introuvable : core/php/acmeRun.php', __FILE__));
        }
        $cmd = 'nohup php ' . escapeshellarg($script);
        foreach ($argv as $arg) {
            $cmd .= ' ' . escapeshellarg($arg);
        }
        $cmd .= ' < /dev/null > /dev/null 2>&1 &';
        log::add('acme', 'debug', '[' . $this->getName() . '] ' . __('Lancement :', __FILE__) . ' ' . $cmd);
        exec($cmd);
    }

    /*
     * Corps de la tâche de fond, appelé par core/php/acmeRun.php en ligne de
     * commande. Prend le verrou de l'équipement pour toute sa durée.
     */
    public function executeJob(string $action, array $args = array()): void {
        $fp = @fopen($this->lockFile(), 'c');
        if ($fp === false) {
            throw new Exception(__('Impossible de créer le verrou', __FILE__) . ' ' . $this->lockFile());
        }
        /* Quelques essais : la page peut sonder le verrou à l'instant précis où
         * la tâche essaie de le prendre. */
        $locked = false;
        for ($i = 0; $i < 15 && !$locked; $i++) {
            $locked = flock($fp, LOCK_EX | LOCK_NB);
            if (!$locked) {
                usleep(200000);
            }
        }
        if (!$locked) {
            fclose($fp);
            log::add('acme', 'warning', '[' . $this->getName() . '] ' . __('Une autre tâche tient déjà le verrou : lancement ignoré.', __FILE__));
            return;
        }
        try {
            $this->writeJob(array('state' => 'running', 'pid' => getmypid()));
            $delay = isset($args['delay']) ? intval($args['delay']) : 0;
            if ($delay > 0) {
                $this->jobLog('info', __('Renouvellement programmé : départ dans', __FILE__) . ' ' . ceil($delay / 60) . ' ' . __('min (étalement des demandes).', __FILE__));
                sleep($delay);
            }
            /* L'objet date du lancement ; après une attente (jusqu'à deux
             * heures pour le cron), l'équipement a pu être supprimé, désactivé
             * ou modifié : on le relit, et c'est la version relue qui travaille. */
            $target = $this;
            if ($delay > 0) {
                $target = self::byId($this->getId());
                if (!is_object($target) || $target->getEqType_name() !== 'acme' || $target->getIsEnable() != 1) {
                    $message = __('Tâche abandonnée : l\'équipement a été supprimé ou désactivé pendant l\'attente.', __FILE__);
                    log::add('acme', 'info', '[' . $this->getName() . '] ' . $message);
                    if (is_object($target)) {
                        $this->writeJob(array('state' => 'success', 'result' => $message, 'finished' => time()));
                    }
                    return;
                }
            }
            $force = !empty($args['force']);
            switch ($action) {
                case 'issue':
                    $result = $target->runIssue($force);
                    $message = $result['message'];
                    break;
                case 'renew':
                    $result = $target->runIssue($force);
                    $message = $result['message'];
                    break;
                case 'staging':
                    $result = $target->runIssue(true, true);
                    $message = $result['message'];
                    break;
                case 'install':
                    $target->runInstall();
                    $message = __('Certificat installé dans le serveur web.', __FILE__);
                    break;
                case 'uninstall':
                    $target->runUninstall();
                    $message = __('Configuration HTTPS retirée du serveur web.', __FILE__);
                    break;
                default:
                    throw new Exception(__('Action inconnue :', __FILE__) . ' ' . $action);
            }
            $this->writeJob(array('state' => 'success', 'result' => $message, 'finished' => time()));
        } catch (Throwable $e) {
            $message = $e->getMessage();
            log::add('acme', 'error', '[' . $this->getName() . '] ' . $message);
            $this->jobLog('error', $message);
            $this->writeJob(array('state' => 'error', 'result' => $message, 'finished' => time()));
            if ($action === 'install' || $action === 'uninstall') {
                try {
                    $this->postMessage('install', $message);
                    if ($action === 'install') {
                        $this->notify('install_error', $message);
                    }
                } catch (Throwable $e2) {
                    log::add('acme', 'error', '[' . $this->getName() . '] ' . $e2->getMessage());
                }
            }
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /* ================================================================== CRON */

    /*
     * Une fois par jour : commandes à jour, renouvellement de ce qui arrive à
     * échéance, alerte si l'échéance approche alors que le renouvellement échoue.
     *
     * Le renouvellement part en tâche de fond (launchJob) et non dans le cron
     * lui-même : le coeur appelle le cronDaily de tous les plugins à la suite,
     * dans le même processus, et une validation DNS peut attendre la
     * propagation plusieurs minutes par certificat. Chaque tâche part en plus
     * avec un délai aléatoire, décalé d'un équipement à l'autre, pour ne pas
     * solliciter l'autorité à heure fixe comme tous les Jeedom du monde.
     */
    public static function cronDaily() {
        /* Le coeur a pu remettre tout le plugin en 775 depuis hier. */
        try {
            self::fixDataRights();
        } catch (Throwable $e) {
            log::add('acme', 'error', 'cronDaily : ' . $e->getMessage());
        }
        $alertDays = max(1, intval(config::byKey('alert_days', 'acme', 14)));
        $index = 0;
        foreach (self::byType('acme', true) as $eqLogic) {
            try {
                $info = $eqLogic->refreshInfo();
                if (!$info['exists']) {
                    continue;
                }
                if ($eqLogic->isRenewalDue()) {
                    if (!$eqLogic->isJobRunning()) {
                        $delay = $index * 600 + random_int(60, 3600);
                        log::add('acme', 'info', '[' . $eqLogic->getName() . '] ' . __('Renouvellement dû :', __FILE__) . ' '
                            . $info['renewalReason'] . ' — ' . __('départ dans', __FILE__) . ' ' . ceil($delay / 60) . ' min');
                        $eqLogic->launchJob('renew', array('delay' => $delay, 'origin' => 'cron'));
                        $index++;
                    }
                } elseif ($eqLogic->needsReinstall() && !$eqLogic->isJobRunning()) {
                    /* Installation ratée après un renouvellement (serveur web
                     * arrêté, sudo indisponible…) : on retente chaque jour. Le
                     * renouvellement, lui, réinstalle de toute façon. */
                    log::add('acme', 'info', '[' . $eqLogic->getName() . '] '
                        . __('Le serveur web ne sert pas le certificat en place : nouvelle tentative d\'installation.', __FILE__));
                    $eqLogic->launchJob('install', array('origin' => 'cron'));
                }
                if ($info['daysLeft'] <= $alertDays) {
                    /* Let's Encrypt n'envoie plus d'e-mail d'expiration : c'est au
                     * plugin de prévenir. Le renouvellement part au tiers de la
                     * durée de vie ; arriver sous le seuil veut dire qu'il n'a pas
                     * eu lieu, quelle qu'en soit la raison. Rappel chaque jour. */
                    $when = ($info['daysLeft'] <= 0)
                        ? __('le certificat a expiré le', __FILE__) . ' ' . $info['expiration']
                        : __('le certificat expire dans', __FILE__) . ' ' . $info['daysLeft'] . ' ' . __('jours', __FILE__) . ' (' . $info['expiration'] . ')';
                    if ($info['last_error'] !== '') {
                        $text = $when . ' ' . __('et son renouvellement échoue :', __FILE__) . ' ' . $info['last_error'];
                    } else {
                        $text = $when . ' ' . __('et n\'a pas encore été renouvelé.', __FILE__);
                    }
                    $eqLogic->postMessage('expiry', $text);
                    $eqLogic->notify('expiry', $text);
                }
            } catch (Throwable $e) {
                log::add('acme', 'error', '[' . $eqLogic->getName() . '] cronDaily : ' . $e->getMessage());
            }
        }
    }

    /* ======================================================== ÉQUIPEMENT */

    /* Normalisation et valeurs par défaut. Ne lève JAMAIS : le coeur crée
     * l'équipement avec son seul nom, et une exception ici rendrait le bouton
     * « Ajouter » définitivement inopérant. La validation a lieu à l'émission. */
    public function preSave() {
        $defaults = array('ca' => 'letsencrypt', 'challenge' => 'dns-01', 'key_type' => 'ec256',
                          'dns_provider' => 'ovh', 'dns_propagation_timeout' => 300, 'https_port' => 443);
        foreach ($defaults as $key => $value) {
            if ((string) $this->getConfiguration($key, '') === '') {
                $this->setConfiguration($key, $value);
            }
        }
        $domains = $this->getDomains();
        $this->setConfiguration('domains', implode("\n", $domains));

        /* Actions de notification : lignes vides écartées, abonnements ramenés
         * à 0/1, identifiant de commande résolu ICI, à l'enregistrement. Le nom
         * lisible devient faux dès qu'on renomme un objet ; l'identifiant, lui,
         * tient. */
        $actions = array();
        foreach ($this->getNotifyActions() as $action) {
            $name = trim(isset($action['cmd']) ? (string) $action['cmd'] : '');
            if ($name === '') {
                continue;
            }
            $events = array();
            foreach (self::notifyDefaultEvents() as $event => $default) {
                $events[$event] = (isset($action['events'][$event]) ? (intval($action['events'][$event]) ? 1 : 0) : $default);
            }
            $actions[] = array(
                'cmd' => $name,
                'cmd_id' => self::notifyActionCmdId(array('cmd' => $name)),
                'options' => (isset($action['options']) && is_array($action['options'])) ? $action['options'] : array(),
                'events' => $events,
            );
        }
        $this->setConfiguration('notify_actions', $actions);

        try {
            $providers = acmeDns::providers();
            $providerId = $this->getConfiguration('dns_provider');
            if (isset($providers[$providerId])) {
                $class = $providers[$providerId];
                foreach ($class::getFields() as $key => $field) {
                    if ((string) $this->getConfiguration('dns_' . $key, '') === '' && isset($field['default'])) {
                        $this->setConfiguration('dns_' . $key, $field['default']);
                    }
                }
            }
        } catch (Throwable $e) {
            log::add('acme', 'debug', 'preSave : ' . $e->getMessage());
        }

        /*
         * Un seul certificat peut être installé dans le serveur web (une seule
         * configuration jeedom-acme-ssl). Deux équipements avec l'installation
         * automatique se remplaceraient l'un l'autre à chaque renouvellement,
         * et le serveur web servirait tantôt l'un, tantôt l'autre.
         *  - équipement neuf (création, duplication d'un équipement qui l'a
         *    cochée) : on ne lève JAMAIS ici, la case est décochée sur le neuf
         *    et on le journalise ;
         *  - équipement existant : refus explicite, rien n'est modifié en
         *    silence ailleurs ; l'utilisateur décide lequel garde la case.
         */
        if ($this->getConfiguration('install_webserver', 0) == 1) {
            $others = array();
            try {
                $others = $this->otherInstallers();
            } catch (Throwable $e) {
                log::add('acme', 'debug', 'preSave : ' . $e->getMessage());
            }
            if (count($others) > 0) {
                if ($this->getId() == '') {
                    $this->setConfiguration('install_webserver', 0);
                    log::add('acme', 'warning', '[' . $this->getName() . '] ' . __('Installation automatique décochée : elle est déjà active sur', __FILE__)
                        . ' ' . $others[0]->getHumanName() . ', ' . __('et le serveur web ne sert qu\'un certificat.', __FILE__));
                } else {
                    throw new Exception(__('Le serveur web ne sert qu\'un certificat, et l\'installation automatique est déjà cochée sur', __FILE__)
                        . ' ' . $others[0]->getHumanName() . '. ' . __('Décochez-la d\'abord sur cet équipement-là.', __FILE__));
                }
            }
        }
    }

    /* Commandes de l'équipement : créées si absentes, jamais renommées (le
     * nom appartient à l'utilisateur une fois la commande créée). */
    public function postSave() {
        $order = 0;
        foreach (self::commandDefinitions() as $logicalId => $def) {
            $order++;
            $cmd = $this->getCmd(null, $logicalId);
            if (is_object($cmd)) {
                continue;
            }
            $cmd = new acmeCmd();
            $cmd->setEqLogic_id($this->getId());
            $cmd->setLogicalId($logicalId);
            $cmd->setName($def['name']);
            $cmd->setType($def['type']);
            $cmd->setSubType($def['subType']);
            $cmd->setOrder($order);
            $cmd->setIsVisible(isset($def['visible']) ? $def['visible'] : 1);
            if (isset($def['unite'])) {
                $cmd->setUnite($def['unite']);
            }
            if (!empty($def['historized'])) {
                $cmd->setIsHistorized(1);
            }
            $cmd->save();
        }
        try {
            $this->refreshInfo();
        } catch (Throwable $e) {
            log::add('acme', 'debug', 'postSave : ' . $e->getMessage());
        }
    }

    /* La suppression d'un équipement emporte ses clés privées. Le serveur web,
     * lui, garde ses copies dans /etc/ssl/jeedom-acme/ et continue de servir le
     * certificat jusqu'à son expiration, sans plus de renouvellement. */
    public function preRemove() {
        try {
            $dir = self::dataDir() . '/certs/' . intval($this->getId());
            if ($this->getId() != '' && is_dir($dir)) {
                self::removeTree($dir);
            }
            if ($this->getConfiguration('install_webserver', 0) == 1) {
                log::add('acme', 'warning', '[' . $this->getName() . '] ' . __('Équipement supprimé alors que son certificat est installé dans le serveur web : il ne sera plus renouvelé. Pensez à « Désinstaller du serveur web » depuis un autre équipement, ou à en recréer un.', __FILE__));
            }
            message::removeAll('acme', 'expiry::' . $this->getId());
            message::removeAll('acme', 'renew::' . $this->getId());
            message::removeAll('acme', 'install::' . $this->getId());
        } catch (Throwable $e) {
            log::add('acme', 'error', 'preRemove : ' . $e->getMessage());
        }
    }

    private static function removeTree(string $dir): void {
        foreach (scandir($dir) as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (is_dir($path) && !is_link($path)) {
                self::removeTree($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    public static function commandDefinitions(): array {
        return array(
            'status' => array('name' => __('Statut', __FILE__), 'type' => 'info', 'subType' => 'string'),
            'expiration' => array('name' => __('Expiration', __FILE__), 'type' => 'info', 'subType' => 'string'),
            'days_left' => array('name' => __('Jours restants', __FILE__), 'type' => 'info', 'subType' => 'numeric', 'unite' => 'j', 'historized' => 1),
            'issuer' => array('name' => __('Émetteur', __FILE__), 'type' => 'info', 'subType' => 'string', 'visible' => 0),
            'last_renewal' => array('name' => __('Dernier renouvellement', __FILE__), 'type' => 'info', 'subType' => 'string'),
            'last_error' => array('name' => __('Dernière erreur', __FILE__), 'type' => 'info', 'subType' => 'string'),
            'renew' => array('name' => __('Renouveler', __FILE__), 'type' => 'action', 'subType' => 'other'),
            'install' => array('name' => __('Installer dans le serveur web', __FILE__), 'type' => 'action', 'subType' => 'other', 'visible' => 0),
        );
    }
}

class acmeCmd extends cmd {

    /* Les actions lancent une tâche de fond : une émission peut durer plusieurs
     * minutes, un scénario ne doit pas rester bloqué dessus. */
    public function execute($_options = array()) {
        $eqLogic = $this->getEqLogic();
        if (!is_object($eqLogic)) {
            return;
        }
        /* Scénarios et cron tournent en ligne de commande. Depuis le web, seul
         * un administrateur peut déclencher une émission ou une installation :
         * un compte « utilisateur » pourrait sinon, en cliquant, épuiser la
         * limite de Let's Encrypt (5 certificats identiques par semaine). */
        if (in_array($this->getLogicalId(), array('renew', 'install'), true) && !acme::isPrivilegedContext()) {
            throw new Exception(__('Action réservée aux administrateurs.', __FILE__));
        }
        switch ($this->getLogicalId()) {
            case 'renew':
                $eqLogic->launchJob('renew', array('force' => 1, 'origin' => 'cmd'));
                break;
            case 'install':
                $eqLogic->launchJob('install', array('origin' => 'cmd'));
                break;
        }
    }
}

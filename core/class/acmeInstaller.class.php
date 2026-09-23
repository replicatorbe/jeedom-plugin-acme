<?php
/* This file is part of the Jeedom plugin acme.
 *
 * Auteur : sMug (Jérôme Fafchamps)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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
 * Pont PHP vers resources/acme_webserver.sh, le seul morceau du plugin qui
 * dépend du système (distribution, serveur web). Indépendant du cœur de
 * Jeedom : utilisable et testable en ligne de commande.
 *
 * Le script est lancé par « sh <script> » (le déploiement ne garantit pas le
 * bit exécutable), précédé de $sudo : Jeedom passe system::getCmdSudo(), qui
 * vaut 'sudo ' ou ''. L'environnement éventuel (ACME_ROOT, ACME_DRYRUN pour
 * les essais) passe par « env », que sudo transmet sans réglage particulier.
 *
 * Chaque action renvoie ['ok' => bool, 'output' => string, 'data' => array,
 * 'code' => int] : output = messages lisibles du script (sa sortie d'erreur),
 * data = ses lignes cle=valeur (valeurs en chaînes), code = code de retour
 * (voir l'en-tête du script). detect() renvoie directement data.
 */
class acmeInstaller {

    /** Durée maximale d'une action du script, en secondes. */
    const TIMEOUT = 180;

    /** @var callable|null */
    private $_logger;
    /** @var string */
    private $_sudo;
    /** @var array<string,string> */
    private $_env = array();
    /** @var string */
    private $_script;

    public function __construct(?callable $logger = null, string $sudo = 'sudo ') {
        $this->_logger = $logger;
        $sudo = trim($sudo);
        $this->_sudo = ($sudo === '') ? '' : $sudo . ' ';
        $this->_script = __DIR__ . '/../../resources/acme_webserver.sh';
    }

    /**
     * Variables d'environnement passées au script (essais) :
     * ['ACME_ROOT' => '/tmp/racine', 'ACME_DRYRUN' => '1'].
     */
    public function setEnvironment(array $env): void {
        $clean = array();
        foreach ($env as $name => $value) {
            if (!is_string($name) || !preg_match('/^[A-Z_][A-Z0-9_]*$/', $name)) {
                throw new InvalidArgumentException('Nom de variable d\'environnement invalide : ' . $name);
            }
            $clean[$name] = (string) $value;
        }
        $this->_env = $clean;
    }

    public function getScriptPath(): string {
        return $this->_script;
    }

    /** Clés de « detect » (os_id, layout, webserver, supported, reason…). */
    public function detect(): array {
        $res = $this->run(array('detect'));
        $data = $res['data'];
        if (!$res['ok']) {
            $data['supported'] = '0';
            if (!isset($data['reason']) || $data['reason'] === '') {
                $data['reason'] = isset($data['error']) ? $data['error'] : trim($res['output']);
            }
        }
        return $data;
    }

    /**
     * Installe le certificat dans le serveur web local.
     * options :
     *   'port'       => 443
     *   'redirect'   => false  redirection HTTP → HTTPS des noms du certificat
     *   'redirect_port' => port HTTPS vu depuis Internet, cible de la
     *                   redirection (défaut : 'port') — routeur qui publie
     *                   Jeedom sur un autre port, ex. 9003 → 443
     *   'webroot'    => '/var/www/html'
     *   'aliases'    => string[]  tous les noms du certificat (le nom principal
     *                   et les jokers « *.x » compris, doublons sans effet).
     *                   Absent : lus dans le certificat (SAN DNS) s'il y en a.
     *   'force_port' => false  installer même si le script ne peut pas vérifier
     *                   que le port est libre (code 12 sinon)
     * $domain est le nom principal, avec ou sans « *. ». Quand des noms sont
     * connus, le script reçoit en --domain le nom nu s'il figure parmi eux,
     * sinon le joker « *.nom » : le nom nu, non couvert par le certificat,
     * n'est alors ni alias ni cible de la redirection.
     */
    public function install(string $domain, string $fullchainPem, string $keyPem, array $options = array()): array {
        $port = isset($options['port']) ? (int) $options['port'] : 443;
        $redirect = !empty($options['redirect']);
        $redirectPort = (isset($options['redirect_port']) && intval($options['redirect_port']) > 0) ? (int) $options['redirect_port'] : $port;
        $webroot = isset($options['webroot']) && $options['webroot'] !== '' ? (string) $options['webroot'] : '/var/www/html';
        $forcePort = !empty($options['force_port']);
        if (isset($options['aliases'])) {
            if (!is_array($options['aliases'])) {
                return $this->failure('L\'option aliases doit être une liste de noms.', 2);
            }
            $names = $options['aliases'];
        } else {
            $names = self::certNames($fullchainPem);
        }
        $resolved = self::resolveNames($domain, $names);
        if ($resolved === null) {
            return $this->failure('Nom principal ou alias invalide (' . $domain . ').', 2);
        }
        list($main, $aliases) = $resolved;

        if (strpos($fullchainPem, '-----BEGIN CERTIFICATE-----') === false) {
            return $this->failure('Le certificat fourni n\'est pas au format PEM.');
        }
        if (!preg_match('/-----BEGIN [A-Z ]*PRIVATE KEY-----/', $keyPem)) {
            return $this->failure('La clé privée fournie n\'est pas au format PEM.');
        }
        // Une clé qui ne correspond pas au certificat passe « apachectl -t »
        // mais empêche Apache de redémarrer : on la refuse dès ici.
        if (function_exists('openssl_x509_check_private_key')) {
            $cert = @openssl_x509_read($fullchainPem);
            if ($cert === false) {
                return $this->failure('Certificat illisible par OpenSSL.');
            }
            if (!@openssl_x509_check_private_key($cert, $keyPem)) {
                return $this->failure('La clé privée ne correspond pas au certificat.');
            }
        }

        $fullchainFile = null;
        $keyFile = null;
        try {
            $fullchainFile = $this->writeTemp($fullchainPem);
            $keyFile = $this->writeTemp($keyPem);
            $args = array(
                'install',
                '--domain', $main,
                '--fullchain', $fullchainFile,
                '--key', $keyFile,
                '--port', (string) $port,
                '--redirect', $redirect ? '1' : '0',
                '--redirect-port', (string) $redirectPort,
                '--webroot', $webroot,
            );
            foreach ($aliases as $alias) {
                $args[] = '--alias';
                $args[] = $alias;
            }
            if ($forcePort) {
                $args[] = '--force-port';
            }
            return $this->run($args);
        } catch (Exception $e) {
            return $this->failure($e->getMessage());
        } finally {
            foreach (array($fullchainFile, $keyFile) as $file) {
                if ($file !== null && file_exists($file)) {
                    @unlink($file);
                }
            }
        }
    }

    /** Test de configuration puis rechargement en douceur. */
    public function reload(): array {
        return $this->run(array('reload'));
    }

    /** Retire ce que le plugin a installé (mod_ssl reste activé). */
    public function uninstall(): array {
        return $this->run(array('uninstall'));
    }

    /** installed, domain, port, fullchain, cert_not_after, days_left… */
    public function status(): array {
        return $this->run(array('status'));
    }

    /**
     * Nom principal et alias à transmettre au script : [main, aliases[]], ou
     * null si un nom n'est pas une chaîne. Le script valide ensuite chaque nom.
     * Sans liste de noms : [domaine tel quel, []] (comportement historique).
     */
    public static function resolveNames(string $domain, array $names): ?array {
        $domain = strtolower(trim($domain));
        $list = array();
        foreach ($names as $name) {
            if (!is_string($name)) {
                return null;
            }
            $name = strtolower(trim($name));
            if ($name !== '' && !in_array($name, $list, true)) {
                $list[] = $name;
            }
        }
        if (count($list) === 0) {
            return array($domain, array());
        }
        $bare = (strpos($domain, '*.') === 0) ? substr($domain, 2) : $domain;
        if (in_array($bare, $list, true)) {
            $main = $bare;
        } elseif (in_array('*.' . $bare, $list, true)) {
            $main = '*.' . $bare;
        } else {
            // Nom principal absent de la liste : gardé tel quel, et couvert.
            $main = $domain;
        }
        return array($main, array_values(array_diff($list, array($main))));
    }

    /** Noms DNS du certificat (extension subjectAltName), en minuscules. */
    public static function certNames(string $fullchainPem): array {
        if (!function_exists('openssl_x509_parse')) {
            return array();
        }
        $info = @openssl_x509_parse($fullchainPem);
        if (!is_array($info) || empty($info['extensions']['subjectAltName'])) {
            return array();
        }
        $names = array();
        foreach (explode(',', (string) $info['extensions']['subjectAltName']) as $entry) {
            $entry = trim($entry);
            if (stripos($entry, 'DNS:') === 0) {
                $names[] = strtolower(trim(substr($entry, 4)));
            }
        }
        return $names;
    }

    // -----------------------------------------------------------------------

    private function log(string $level, string $message): void {
        if ($this->_logger !== null) {
            call_user_func($this->_logger, $level, $message);
        }
    }

    private function failure(string $message, int $code = 1): array {
        $this->log('error', $message);
        return array(
            'ok' => false,
            'output' => $message,
            'data' => array('result' => 'error', 'error' => $message),
            'code' => $code,
        );
    }

    /** Fichier temporaire 0600 (tempnam le crée déjà ainsi ; on s'en assure). */
    private function writeTemp(string $content): string {
        $file = tempnam(sys_get_temp_dir(), 'acme');
        if ($file === false) {
            throw new RuntimeException('Impossible de créer un fichier temporaire dans ' . sys_get_temp_dir());
        }
        @chmod($file, 0600);
        if (file_put_contents($file, $content) !== strlen($content)) {
            @unlink($file);
            throw new RuntimeException('Impossible d\'écrire le fichier temporaire ' . $file);
        }
        return $file;
    }

    /** Commande complète, chaque argument protégé. */
    private function buildCommand(array $args): string {
        $cmd = $this->_sudo;
        if (count($this->_env) > 0) {
            $cmd .= 'env';
            foreach ($this->_env as $name => $value) {
                $cmd .= ' ' . escapeshellarg($name . '=' . $value);
            }
            $cmd .= ' ';
        }
        $cmd .= 'sh ' . escapeshellarg($this->_script);
        foreach ($args as $arg) {
            $cmd .= ' ' . escapeshellarg((string) $arg);
        }
        return $cmd;
    }

    /** Lance le script, capture stdout et stderr séparément. */
    private function run(array $args): array {
        if (!is_readable($this->_script)) {
            return $this->failure('Script introuvable : ' . $this->_script);
        }
        $cmd = $this->buildCommand($args);
        $this->log('debug', 'Commande : ' . $cmd);

        $pipes = array();
        $proc = proc_open($cmd, array(
            0 => array('file', '/dev/null', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        ), $pipes);
        if (!is_resource($proc)) {
            return $this->failure('Impossible de lancer : ' . $cmd);
        }

        // Lecture des deux flux en parallèle : lire l'un puis l'autre peut
        // bloquer si le script remplit le tampon du second.
        $stdout = '';
        $stderr = '';
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $open = array(1 => $pipes[1], 2 => $pipes[2]);
        $deadline = time() + self::TIMEOUT;
        $timedOut = false;
        while (count($open) > 0) {
            if (time() > $deadline) {
                $timedOut = true;
                break;
            }
            $read = array_values($open);
            $write = null;
            $except = null;
            if (@stream_select($read, $write, $except, 1) === false) {
                break;
            }
            foreach ($read as $stream) {
                $chunk = fread($stream, 8192);
                $key = ($stream === $pipes[1]) ? 1 : 2;
                if ($chunk !== false && $chunk !== '') {
                    if ($key === 1) {
                        $stdout .= $chunk;
                    } else {
                        $stderr .= $chunk;
                    }
                } elseif (feof($stream)) {
                    unset($open[$key]);
                }
            }
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        if ($timedOut) {
            proc_terminate($proc);
            proc_close($proc);
            return $this->failure('Délai dépassé (' . self::TIMEOUT . ' s) pour : ' . $args[0]);
        }
        $code = proc_close($proc);

        foreach (preg_split('/\r?\n/', trim($stderr)) as $line) {
            if ($line === '') {
                continue;
            }
            if (strpos($line, 'ERREUR') === 0) {
                $level = 'error';
            } elseif (strpos($line, 'ATTENTION') === 0) {
                $level = 'warning';
            } elseif (strpos($line, '[simulation]') === 0 || strpos($line, '  | ') === 0) {
                $level = 'debug';
            } else {
                $level = 'info';
            }
            $this->log($level, $line);
        }

        $data = self::parseOutput($stdout);
        $ok = ($code === 0) && (!isset($data['result']) || $data['result'] === 'ok');
        if (!$ok && $code === 0) {
            $code = 1;
        }
        return array(
            'ok' => $ok,
            'output' => trim($stderr),
            'data' => $data,
            'code' => $code,
        );
    }

    /** Lignes cle=valeur → tableau (les autres lignes sont ignorées). */
    public static function parseOutput(string $stdout): array {
        $data = array();
        foreach (preg_split('/\r?\n/', $stdout) as $line) {
            if (preg_match('/^([a-z0-9_]+)=(.*)$/', $line, $m)) {
                $data[$m[1]] = $m[2];
            }
        }
        return $data;
    }
}

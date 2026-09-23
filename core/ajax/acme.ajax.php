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

try {
    require_once __DIR__ . '/../../../../core/php/core.inc.php';
    include_file('core', 'authentification', 'php');

    /* Ces actions touchent aux clés privées et à la configuration du serveur
     * web (en root, via sudo) : administrateurs seulement, toutes. */
    if (!isConnect('admin')) {
        throw new Exception(__('401 - Accès non autorisé', __FILE__));
    }

    /*
     * ajax::init() sans liste d'actions autorisées en GET : toute action passée
     * en GET est refusée, ce qui interdit de lancer une émission ou de
     * télécharger une clé par un simple lien.
     *
     * Contre les requêtes forgées depuis un autre site : le cookie de session
     * de Jeedom est SameSite=Strict, et Jeedom 4.4+ n'a plus de jeton CSRF. On
     * exige en plus l'en-tête X-Requested-With, qu'un formulaire ne sait pas
     * poser et qu'une requête d'un autre site ne peut poser sans une
     * autorisation CORS que Jeedom ne donne pas. (domUtils.ajax ne le pose pas :
     * desktop/js/acme.js passe par fetch directement.)
     */
    ajax::init();
    if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || $_SERVER['HTTP_X_REQUESTED_WITH'] !== 'XMLHttpRequest') {
        throw new Exception(__('Requête refusée : en-tête X-Requested-With absent.', __FILE__));
    }

    /* Plugin désactivé : sa classe n'est plus chargée par le coeur, et l'appel
     * finirait sur « Class acme not found ». */
    if (!plugin::byId('acme')->isActive()) {
        throw new Exception(__('Le plugin ACME est désactivé.', __FILE__));
    }
    class_exists('acme');

    /* Équipement désigné par init('id'), en vérifiant qu'il est bien à nous. */
    $getEqLogic = function () {
        $eqLogic = acme::byId(init('id'));
        if (!is_object($eqLogic) || $eqLogic->getEqType_name() !== 'acme') {
            throw new Exception(__('Équipement introuvable :', __FILE__) . ' ' . init('id'));
        }
        return $eqLogic;
    };

    $action = init('action');

    /* Lance une tâche de fond : issue, staging, renew, install, uninstall. */
    if ($action == 'launch') {
        unautorizedInDemo();
        $eqLogic = $getEqLogic();
        $job = init('job');
        if (!in_array($job, array('issue', 'staging', 'renew', 'install', 'uninstall'), true)) {
            throw new Exception(__('Tâche inconnue :', __FILE__) . ' ' . $job);
        }
        log::add('acme', 'info', '[' . $eqLogic->getName() . '] ' . __('Tâche demandée par', __FILE__) . ' '
                 . $_SESSION['user']->getLogin() . ' : ' . $job);
        $eqLogic->launchJob($job, array('force' => ($job === 'renew') ? 1 : 0, 'origin' => 'user'));
        ajax::success($eqLogic->getJobStatus());
    }

    /* Avancement de la tâche, et état du certificat dans la même réponse : la
     * page interroge toutes les deux secondes, autant n'en faire qu'un appel. */
    if ($action == 'jobStatus') {
        $eqLogic = $getEqLogic();
        ajax::success(array(
            'job' => $eqLogic->getJobStatus(),
            'cert' => $eqLogic->getCertificateInfo(),
            'test' => $eqLogic->getCertificateInfo(true),
        ));
    }

    if ($action == 'certInfo') {
        $eqLogic = $getEqLogic();
        ajax::success(array(
            'cert' => $eqLogic->refreshInfo(),
            'test' => $eqLogic->getCertificateInfo(true),
        ));
    }

    /*
     * Test des accès au fournisseur DNS, avec les valeurs du formulaire (pas
     * besoin d'enregistrer avant). Un champ laissé vide reprend la valeur
     * enregistrée de l'équipement, s'il y en a un.
     */
    if ($action == 'testDns') {
        $providerId = init('provider');
        $providers = acmeDns::providers();
        if (!isset($providers[$providerId])) {
            throw new Exception(__('Fournisseur DNS inconnu :', __FILE__) . ' ' . $providerId);
        }
        $posted = is_json(init('config'), array());
        if (!is_array($posted)) {
            $posted = array();
        }
        $saved = null;
        if (init('id') != '') {
            $saved = acme::byId(init('id'));
            if (!is_object($saved) || $saved->getEqType_name() !== 'acme') {
                $saved = null;
            }
        }
        $class = $providers[$providerId];
        $config = array();
        foreach ($class::getFields() as $key => $field) {
            $value = isset($posted[$key]) ? trim((string) $posted[$key]) : '';
            /* Le masque de acme::toArray() n'est jamais une vraie valeur. */
            if ($value === acme::SECRET_MASK) {
                $value = '';
            }
            if ($value === '' && $saved !== null) {
                $value = trim((string) $saved->getConfiguration('dns_' . $key, ''));
            }
            if ($value === '' && isset($field['default'])) {
                $value = (string) $field['default'];
            }
            $config[$key] = $value;
        }
        $lines = array();
        $logger = function ($level, $message) use (&$lines) {
            log::add('acme', in_array($level, array('debug', 'info', 'warning', 'error'), true) ? $level : 'info', '[testDns] ' . $message);
            if ($level !== 'debug') {
                $lines[] = (string) $message;
            }
        };
        $provider = acmeDns::create($providerId, $config, $logger);
        $summary = $provider->test();
        ajax::success(array('summary' => $summary, 'lines' => $lines));
    }

    /* Essai des notifications : toutes les actions ENREGISTRÉES de
     * l'équipement sont exécutées, quel que soit leur abonnement. */
    if ($action == 'testNotify') {
        $eqLogic = acme::byId(init('id'));
        if (!is_object($eqLogic) || $eqLogic->getEqType_name() !== 'acme') {
            throw new Exception(__('Équipement introuvable :', __FILE__) . ' ' . init('id'));
        }
        if (count($eqLogic->getNotifyActions()) === 0) {
            throw new Exception(__('Aucune action de notification enregistrée : ajoutez-en une, puis sauvegardez l\'équipement.', __FILE__));
        }
        $report = $eqLogic->notify('test', __('Ceci est un essai des notifications du plugin ACME. Si vous lisez ce message, elles fonctionnent.', __FILE__));
        ajax::success(array('report' => $report));
    }

    /* Compatibilité du système avec l'installation automatique en HTTPS. */
    if ($action == 'detectSystem') {
        $installer = new acmeInstaller(function ($level, $message) {
            log::add('acme', in_array($level, array('debug', 'info', 'warning', 'error'), true) ? $level : 'info', '[detect] ' . $message);
        }, system::getCmdSudo());
        ajax::success($installer->detect());
    }

    /*
     * Téléchargement d'un fichier du certificat en place, renvoyé en texte : le
     * navigateur en fait un fichier. Liste fermée : jamais la clé du compte
     * ACME, jamais un chemin fourni par la requête.
     */
    if ($action == 'download') {
        unautorizedInDemo();
        $eqLogic = $getEqLogic();
        $files = array('fullchain' => 'fullchain.pem', 'cert' => 'cert.pem', 'chain' => 'chain.pem', 'privkey' => 'privkey.pem');
        $which = init('file');
        if (!isset($files[$which])) {
            throw new Exception(__('Fichier inconnu :', __FILE__) . ' ' . $which);
        }
        $path = $eqLogic->certDir() . '/' . $files[$which];
        if (!is_file($path)) {
            throw new Exception(__('Aucun certificat pour cet équipement : obtenez-le d\'abord.', __FILE__));
        }
        if ($which === 'privkey') {
            /* Niveau warning : la sortie d'une clé privée se trace même quand le
             * journal n'est pas en mode info. */
            log::add('acme', 'warning', '[' . $eqLogic->getName() . '] ' . __('Clé privée du certificat téléchargée par', __FILE__)
                     . ' ' . $_SESSION['user']->getLogin() . ' ' . __('depuis', __FILE__) . ' ' . getClientIp());
        }
        $domains = $eqLogic->getDomains();
        $base = isset($domains[0]) ? preg_replace('/[^a-z0-9.-]+/', '_', str_replace('*.', 'wildcard.', $domains[0])) : 'acme';
        ajax::success(array(
            'filename' => $base . '-' . $files[$which],
            'content' => (string) file_get_contents($path),
        ));
    }

    throw new Exception(__('Aucune méthode correspondante à :', __FILE__) . ' ' . $action);

} catch (Throwable $e) {
    /* Throwable et non Exception : en PHP 8 une Error (méthode inexistante,
     * erreur de type) n'hérite pas d'Exception et donnerait un HTTP 500 muet. */
    ajax::error(displayException($e), $e->getCode());
}

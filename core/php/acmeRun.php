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
 * Tâche de fond du plugin acme, lancée détachée par acme::launchJob() :
 *
 *   php acmeRun.php id=<eqLogic> action=issue|staging|renew|install|uninstall [force=1] [delay=<s>] [origin=cron]
 *
 * Ligne de commande UNIQUEMENT. Ce fichier est sous la racine web : appelé par
 * HTTP, il permettrait à n'importe qui de déclencher des émissions de
 * certificats et des modifications du serveur web. Le .htaccess du dossier le
 * refuse déjà ; ce contrôle tient même sans lui (nginx, AllowOverride None).
 */
if (php_sapi_name() !== 'cli' || isset($_SERVER['REQUEST_METHOD']) || !isset($argv)) {
    if (!headers_sent()) {
        header('HTTP/1.1 403 Forbidden');
    }
    echo "403 - Forbidden\n";
    exit(1);
}

require_once __DIR__ . '/../../../../core/php/core.inc.php';

/* Arguments cle=valeur. */
$args = array();
foreach (array_slice($argv, 1) as $arg) {
    $pos = strpos($arg, '=');
    if ($pos !== false) {
        $args[substr($arg, 0, $pos)] = substr($arg, $pos + 1);
    }
}

try {
    if (!class_exists('acme')) {
        throw new Exception('Classe acme introuvable : le plugin est-il activé ?');
    }
    $id = isset($args['id']) ? intval($args['id']) : 0;
    $action = isset($args['action']) ? (string) $args['action'] : '';
    $eqLogic = acme::byId($id);
    if (!is_object($eqLogic) || $eqLogic->getEqType_name() !== 'acme') {
        throw new Exception('Équipement acme introuvable : ' . $id);
    }
    /* Pas de limite de durée : une propagation DNS peut prendre plusieurs
     * minutes ; les bibliothèques bornent elles-mêmes leurs attentes. */
    set_time_limit(0);
    $eqLogic->executeJob($action, array(
        'force' => !empty($args['force']),
        'delay' => isset($args['delay']) ? intval($args['delay']) : 0,
        'origin' => isset($args['origin']) ? (string) $args['origin'] : 'user',
    ));
} catch (Throwable $e) {
    log::add('acme', 'error', 'acmeRun : ' . $e->getMessage());
    exit(1);
}
exit(0);

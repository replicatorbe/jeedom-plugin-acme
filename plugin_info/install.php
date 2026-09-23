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

require_once __DIR__ . '/../../../core/php/core.inc.php';

/*
 * Prépare le dossier data/ (0700, avec son .htaccess) et les réglages par
 * défaut. data/ n'est ni dans le dépôt ni dans le déploiement : il naît ici,
 * ou au premier usage si l'installation a eu lieu par copie de fichiers.
 */
function acme_prepare() {
    acme::dataDir();
    acme::ensureDir(acme::dataDir() . '/accounts');
    acme::ensureDir(acme::dataDir() . '/certs');
    if (config::byKey('alert_days', 'acme', '') === '') {
        config::save('alert_days', 14, 'acme');
    }
    /* Le coeur vient de faire un « chmod 775 -R » sur le plugin : clés
     * privées de nouveau en 0600, dossiers en 0700. */
    acme::fixDataRights();
}

/*
 * Une version précédente permettait de cocher l'installation automatique sur
 * plusieurs équipements, alors que le serveur web ne sert qu'un certificat.
 * preSave refuse désormais ce cas sur un équipement existant : on le corrige
 * donc avant de réenregistrer, sinon la mise à jour échouerait sur ces
 * équipements. On garde la case sur celui dont le certificat est installé
 * (installed_at le plus récent), à défaut sur le premier.
 */
function acme_dedupe_install_webserver() {
    $keep = null;
    $keepAt = -1;
    $flagged = array();
    foreach (eqLogic::byType('acme') as $eqLogic) {
        if ($eqLogic->getConfiguration('install_webserver', 0) != 1) {
            continue;
        }
        $flagged[] = $eqLogic;
        $at = 0;
        try {
            $state = $eqLogic->readState();
            $at = intval($state['installed_at']);
        } catch (Throwable $e) {
        }
        if ($at > $keepAt) {
            $keep = $eqLogic;
            $keepAt = $at;
        }
    }
    if (count($flagged) < 2) {
        return;
    }
    foreach ($flagged as $eqLogic) {
        if ($eqLogic->getId() == $keep->getId()) {
            continue;
        }
        $eqLogic->setConfiguration('install_webserver', 0);
        $eqLogic->save(true);
        log::add('acme', 'warning', __('Installation automatique décochée sur', __FILE__) . ' ' . $eqLogic->getHumanName()
                 . ' : ' . __('un seul certificat peut être installé dans le serveur web, elle reste active sur', __FILE__)
                 . ' ' . $keep->getHumanName() . '.');
    }
}

function acme_install() {
    try {
        acme_prepare();
    } catch (Throwable $e) {
        log::add('acme', 'error', __('Installation du plugin :', __FILE__) . ' ' . $e->getMessage());
    }
}

/*
 * Appelée à chaque mise à jour, par un processus PHP que la requête attend :
 * rien de lent ni de réseau ici. Les commandes manquantes d'une nouvelle
 * version sont créées par postSave, en réenregistrant chaque équipement.
 */
function acme_update() {
    try {
        acme_prepare();
        try {
            acme_dedupe_install_webserver();
        } catch (Throwable $e) {
            log::add('acme', 'error', __('Mise à jour du plugin :', __FILE__) . ' ' . $e->getMessage());
        }
        foreach (eqLogic::byType('acme') as $eqLogic) {
            try {
                $eqLogic->save();
            } catch (Throwable $e) {
                log::add('acme', 'error', __('Mise à jour de l\'équipement', __FILE__) . ' ' . $eqLogic->getHumanName() . ' : ' . $e->getMessage());
            }
        }
    } catch (Throwable $e) {
        log::add('acme', 'error', __('Mise à jour du plugin :', __FILE__) . ' ' . $e->getMessage());
    }
}

/*
 * Appelée à la désactivation comme à la désinstallation : le coeur ne
 * distingue pas les deux.
 *
 * La configuration HTTPS du serveur web n'est PAS retirée : elle pointe vers
 * des copies des certificats dans /etc/ssl/jeedom-acme/, indépendantes du
 * plugin, et la retirer ici couperait sans prévenir l'accès à Jeedom en HTTPS
 * — peut-être celui par lequel l'utilisateur est en train de naviguer. La
 * documentation explique comment la retirer proprement, avec le bouton
 * « Désinstaller du serveur web », avant de supprimer le plugin.
 *
 * Les clés (data/) restent aussi : une simple désactivation ne doit pas faire
 * perdre le compte ACME. Le coeur supprime le dossier du plugin à la
 * désinstallation, data/ compris.
 */
function acme_remove() {
    try {
        message::removeAll('acme');
    } catch (Throwable $e) {
        log::add('acme', 'error', __('Désinstallation du plugin :', __FILE__) . ' ' . $e->getMessage());
    }
}

# Plugin Jeedom — ACME (Let's Encrypt)

Obtient et renouvelle automatiquement un **certificat TLS gratuit** pour votre
Jeedom auprès de Let's Encrypt, de ZeroSSL ou de toute autorité ACME, puis
l'installe dans le serveur web de Jeedom pour passer en **HTTPS**.

Parce qu'un Jeedom en `http://` sur le réseau local, c'est un mot de passe
administrateur qui circule en clair, et un navigateur qui refuse la caméra, le
micro ou les notifications.

## Ce qu'il sait faire

**Valider sans rien ouvrir.** La validation DNS-01 passe par l'API du
fournisseur DNS (OVHcloud pour l'instant) : aucun port à ouvrir sur le
routeur, fonctionne pour un Jeedom purement local, et permet les certificats
génériques `*.mondomaine.fr`. HTTP-01 est là aussi, pour qui a le port 80
public redirigé vers Jeedom.

**Essayer avant de demander.** Le bouton « Tester (staging) » fait une émission
complète sur le serveur de test de Let's Encrypt : sans limite de taux, sans
rien installer, sans toucher au vrai certificat.

**Installer sans casser.** Le certificat est copié dans `/etc/ssl/jeedom-acme/`
et le serveur web configuré en HTTPS, après sauvegarde et test de
configuration ; si le test échoue, tout est restauré. Apache sur Debian,
Raspberry Pi OS, Ubuntu, Docker, RHEL et Alpine ; nginx en semi-automatique
(avec l'obligatoire `location ^~ /plugins/acme/data/ { deny all; }`).

**Renouveler et prévenir.** Chaque jour, au dernier tiers de la durée de vie du
certificat, en tâche de fond et à une heure étalée. Let's Encrypt n'envoie plus
d'e-mails d'expiration : si l'échéance approche alors que le renouvellement
échoue, le plugin crée un message dans Jeedom.

**Sans dépendance.** Ni certbot, ni acme.sh, ni Composer : le protocole ACME
(RFC 8555) est implémenté en PHP, avec les seules extensions que Jeedom exige
déjà. PHP 7.4 à 8.4.

## Installation

1. Installer le plugin depuis le Market (ou par la source GitHub, branche
   `beta`), puis l'activer.
2. Dans la configuration du plugin, renseigner l'e-mail de contact (facultatif
   pour Let's Encrypt) et, au besoin, **Analyser le système**.
3. **Plugins → Sécurité → ACME (Let's Encrypt)** : ajouter un certificat,
   saisir le domaine, choisir la validation, **Tester (staging)**, puis
   **Obtenir le certificat**.
4. **Installer dans le serveur web** (ou cocher l'installation automatique
   avant d'obtenir le certificat), vérifier `https://<nom>`, et seulement
   ensuite activer la redirection HTTP → HTTPS. Depuis le réseau local, le nom
   doit résoudre vers l'adresse IP locale de Jeedom (DNS local du routeur ou
   Pi-hole, enregistrement A public vers l'adresse privée, ou NAT loopback).

La documentation complète est dans [docs/fr_FR/index.md](docs/fr_FR/index.md)
([English](docs/en_US/index.md)).

## Organisation du code

| Fichier | Rôle |
|---|---|
| `core/class/acmeCrypto.class.php` | clés, JWK, signatures JWS, CSR, lecture des certificats |
| `core/class/acmeClient.class.php` | client ACME (RFC 8555), EAB, ZeroSSL |
| `core/class/acmeSolver.class.php` | défis HTTP-01 et DNS-01 |
| `core/class/acmeDns.class.php`, `acmeDnsOvh.class.php` | fournisseurs DNS, vérification de propagation |
| `core/class/acmeInstaller.class.php`, `resources/acme_webserver.sh` | installation dans le serveur web (script POSIX, en root) |
| `core/class/acme.class.php` | intégration Jeedom : équipements, commandes, tâches de fond, cron |
| `core/php/acmeRun.php` | tâche de fond (ligne de commande uniquement) |
| `core/ajax/acme.ajax.php` | actions de l'interface (administrateurs) |

Les bibliothèques ne dépendent pas de Jeedom et se testent en ligne de
commande (`tests/`). `php tests/check-classes.php` contrôle, contre le cœur
installé, les pièges qui cassent un plugin en silence.

## Licence

AGPL-3.0 — voir [LICENSE](LICENSE). Auteur : sMug (Jérôme Fafchamps).

Ce plugin n'est affilié ni à Let's Encrypt / ISRG, ni à ZeroSSL, ni à OVHcloud.

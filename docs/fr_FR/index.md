# Plugin ACME (Let's Encrypt)

Obtient et renouvelle automatiquement un **certificat TLS gratuit** pour votre
Jeedom auprès de Let's Encrypt, de ZeroSSL ou de toute autorité compatible
ACME, puis l'installe si vous le souhaitez dans le serveur web de Jeedom pour
passer en **HTTPS**.

- **Validation DNS-01** par l'API de votre fournisseur DNS (OVHcloud pour
  l'instant) : aucun port à ouvrir sur le routeur, fonctionne pour un Jeedom
  purement local, et permet les certificats génériques (`*.mondomaine.fr`).
- **Validation HTTP-01** pour qui a déjà le port 80 public redirigé vers Jeedom.
- **Renouvellement automatique** chaque jour, avec des **alertes** dans le
  centre de messages et par les commandes de votre choix (mail, Telegram,
  SMS…) si l'échéance approche ou si un renouvellement échoue.
- **Installation dans le serveur web** (Apache ; nginx en semi-automatique),
  avec sauvegarde, test de configuration et retour arrière automatique.
- **Aucune dépendance** : ni certbot, ni acme.sh, ni paquet à installer. Le
  plugin est écrit en PHP, avec les seules extensions que Jeedom exige déjà.

## Sommaire

1. [Prérequis](#prérequis)
2. [Principe](#principe)
3. [DNS-01 ou HTTP-01 ?](#dns-01-ou-http-01-)
4. [Pas-à-pas : OVHcloud en DNS-01](#pas-à-pas--ovhcloud-en-dns-01)
5. [Pas-à-pas : HTTP-01](#pas-à-pas--http-01)
6. [Autorités : Let's Encrypt, staging, ZeroSSL, autre](#autorités--lets-encrypt-staging-zerossl-autre)
7. [Installation dans le serveur web](#installation-dans-le-serveur-web)
8. [Docker](#docker)
9. [nginx](#nginx)
10. [Renouvellement et alertes](#renouvellement-et-alertes)
11. [Commandes](#commandes)
12. [Désinstallation propre](#désinstallation-propre)
13. [Dépannage](#dépannage)
14. [FAQ](#faq)

## Prérequis

- **Un nom de domaine public** qui vous appartient, par exemple
  `jeedom.mondomaine.fr`. Aucune autorité publique ne certifie un nom privé :
  `jeedom.local`, `maison.lan`, `box.home` ou une adresse IP comme
  `192.168.1.10` sont refusés, par l'autorité comme par le plugin.
- Le nom **n'a pas besoin de pointer vers votre adresse publique** en DNS-01 :
  il peut désigner l'adresse locale de Jeedom (`192.168.1.10`) dans votre DNS
  public, ou seulement dans celui de votre box. En HTTP-01, en revanche, il
  doit pointer vers votre adresse IP publique.
- Pour la validation DNS-01 : un domaine dont la zone DNS est hébergée chez un
  fournisseur pris en charge (OVHcloud).
- Jeedom 4.4 ou plus récent, PHP 7.4 à 8.4 (installation officielle, Smart,
  Luna, Atlas, Raspberry Pi, Docker, installation manuelle).

## Principe

Un **équipement** du plugin est **un certificat**. Vous y saisissez le ou les
domaines, l'autorité, la méthode de validation, et, si vous le souhaitez,
l'installation dans le serveur web.

1. **Tester (staging)** : essai complet auprès du serveur de test de Let's
   Encrypt. Sans limite de taux, et rien n'est installé. À faire d'abord.
2. **Obtenir le certificat** : la vraie demande. Selon la méthode choisie, le
   plugin pose un enregistrement DNS ou un fichier, l'autorité vérifie,
   délivre le certificat, et le plugin retire ce qu'il a posé.
3. **Installer dans le serveur web** : bouton du même nom, ou case
   « Installer automatiquement » cochée *avant* d'obtenir le certificat (il est
   alors installé dès sa délivrance, puis à chaque renouvellement). Le serveur
   web est rechargé en douceur.
4. **Vérifier** que `https://<votre nom>` s'ouvre sans alerte du navigateur.
5. **Seulement ensuite**, activer **Rediriger HTTP vers HTTPS**, puis
   réinstaller.
6. Chaque jour, le plugin vérifie l'échéance et renouvelle quand il le faut.

> **Depuis le réseau local, le nom doit désigner l'adresse IP locale de
> Jeedom**, sinon le navigateur ne le trouvera pas par ce nom. Trois
> solutions, au choix :
> - un **DNS local** qui répond l'adresse locale pour ce nom (DNS du routeur,
>   Pi-hole, AdGuard Home…) ;
> - un **enregistrement A public** qui pointe vers l'adresse privée
>   (`jeedom.mondomaine.fr → 192.168.1.10`) : sans danger, cette adresse n'est
>   joignable que chez vous ; possible en DNS-01 seulement ;
> - le **NAT loopback** (ou *hairpin NAT*) du routeur, si le nom pointe vers
>   votre adresse publique et que le routeur sait renvoyer vers Jeedom les
>   connexions venues de l'intérieur.

Une émission peut durer plusieurs minutes (attente de la propagation DNS). Elle
tourne donc **en tâche de fond** : la page affiche l'étape en cours et les
dernières lignes du journal, et vous pouvez la quitter sans rien interrompre.

Les clés et certificats sont rangés dans le dossier `data/` du plugin
(dossiers en `0700`, fichiers en `0600`, accès web refusé). Le compte ACME est
créé une fois par autorité, puis réutilisé.

## DNS-01 ou HTTP-01 ?

Pour prouver que vous contrôlez le domaine, l'autorité propose deux épreuves.

| | DNS-01 (recommandé) | HTTP-01 |
|---|---|---|
| Ce que fait le plugin | pose un enregistrement TXT `_acme-challenge.<domaine>` par l'API du fournisseur DNS | dépose un fichier dans `/.well-known/acme-challenge/` |
| Port à ouvrir sur le routeur | **aucun** | **port public 80 → Jeedom:80**, obligatoirement |
| Jeedom purement local | oui | non |
| Certificat générique `*.domaine` | oui | non |
| Ce qu'il faut | des clés d'API chez le fournisseur DNS | le nom pointe vers votre IP publique, port 80 redirigé |

### Le piège du HTTP-01 : le port 80, et rien d'autre

L'autorité se connecte **toujours au port 80** de l'adresse publique du nom.
Elle suit les redirections HTTP, mais **seulement vers les ports 80 et 443**.

```
                        Internet                           Réseau local
 Let's Encrypt ──http://jeedom.mondomaine.fr:80──▶ Routeur ──────────▶ Jeedom:80    ✔ fonctionne
                                                  (NAT 80 → 192.168.1.10:80)

 Let's Encrypt ──http://jeedom.mondomaine.fr:80──▶ Routeur    rien sur le port 80  ✘ échec
                                                  (NAT 9002 → 192.168.1.10:80)
```

Une redirection du routeur « port public **9002** → Jeedom:80 », très courante
pour accéder à Jeedom de l'extérieur, **ne suffit pas** : l'autorité ne
viendra jamais sur le port 9002. Il faut « port public **80** → Jeedom:80 ».
Si le port 80 public est déjà pris (autre serveur, box qui le réserve), ou si
vous ne voulez rien ouvrir : prenez **DNS-01**.

## Pas-à-pas : OVHcloud en DNS-01

### 1. Créer un jeton d'API aux droits restreints

1. Sur la fiche de l'équipement, choisissez **Méthode : DNS-01**,
   **Fournisseur DNS : OVHcloud**, puis le **point d'accès de l'API** :
   - **OVHcloud Europe** (`ovh-eu`) pour un compte OVH européen : le cas
     général en France et en Belgique ;
   - `ovh-ca` / `ovh-us` pour les comptes canadiens et américains ;
   - `kimsufi-*` et `soyoustart-*` pour ces marques.
2. Cliquez sur **Créer un jeton OVH**. La page de création de jeton d'OVHcloud
   s'ouvre, déjà remplie avec les seuls droits nécessaires :
   - `GET /domain/zone`
   - `GET /domain/zone/*`
   - `POST /domain/zone/*`
   - `DELETE /domain/zone/*`
3. Connectez-vous avec le compte OVH qui gère le domaine, donnez un nom à
   l'application (par exemple « Jeedom ACME »), et choisissez une **validité
   illimitée** (*Unlimited*) : sinon les renouvellements automatiques
   s'arrêteront à l'expiration du jeton.
4. Pour aller plus loin dans la restriction, remplacez `*` par le nom de votre
   zone : `/domain/zone/mondomaine.fr/*` (et gardez `GET /domain/zone`, qui
   sert à trouver la zone).
5. OVHcloud affiche trois valeurs : **Application Key**, **Application
   Secret** et **Consumer Key**. L'Application Secret n'est montré qu'une fois.

### 2. Renseigner l'équipement

1. Recopiez les trois clés dans les champs correspondants.
2. Cliquez sur **Tester l'accès DNS** : le plugin vérifie les clés et les
   droits auprès d'OVHcloud et résume ce qu'il voit, sans rien modifier dans
   la zone. Les champs sont pris tels que saisis : inutile d'enregistrer avant.
3. Saisissez le ou les **domaines**, par exemple `jeedom.mondomaine.fr`.
4. **Sauvegardez**, puis **Tester (staging)**. Suivez l'avancement dans le
   cadre « Tâche en cours » : pose de l'enregistrement TXT, attente de
   propagation sur les serveurs DNS d'OVH, validation, retrait.
5. Si l'essai réussit : **Obtenir le certificat**.
6. **Installer dans le serveur web** (ou cochez l'installation automatique
   avant l'étape 5), vérifiez `https://jeedom.mondomaine.fr`, et seulement
   ensuite activez la redirection HTTP → HTTPS (voir
   [Installation dans le serveur web](#installation-dans-le-serveur-web)).

L'**attente de propagation** (**300 s par défaut**, réglable de 30 à 3600 s sur
l'équipement) borne le temps d'attente de l'enregistrement TXT sur tous les
serveurs faisant autorité pour la zone. Le plugin les interroge directement ;
si le port 53 sortant est bloqué, il passe par DNS-over-HTTPS (Cloudflare,
Google).

Si l'enregistrement n'est toujours pas visible partout à la fin de ce délai, le
plugin **s'arrête en erreur sans demander la validation à l'autorité** :
l'enregistrement est retiré et **aucune tentative Let's Encrypt n'est
consommée** (les échecs de validation sont limités par heure). Augmentez le
délai et relancez.

## Pas-à-pas : HTTP-01

1. Sur le routeur : redirigez le **port public 80** vers **Jeedom, port 80**
   (voir [le piège du HTTP-01](#le-piège-du-http-01--le-port-80-et-rien-dautre)).
2. Dans le DNS public : le nom doit pointer vers votre **adresse IP publique**.
3. Sur la fiche de l'équipement : **Méthode : HTTP-01**. La **racine web**
   vide convient pour une installation standard (racine de Jeedom).
4. Sauvegardez, **Tester (staging)**, puis **Obtenir le certificat**.
5. **Installer dans le serveur web**, vérifiez `https://<votre nom>`, puis
   seulement activez la redirection. Depuis la maison, le nom pointe ici vers
   votre adresse publique : il faut le NAT loopback du routeur ou un DNS local
   (voir [Principe](#principe)).

Avant de solliciter l'autorité, le plugin vérifie qu'il peut lire lui-même le
fichier de défi. S'il n'y arrive pas par l'adresse publique, c'est souvent que
votre routeur ne fait pas de « NAT loopback » : ce n'est pas bloquant,
l'autorité, elle, vient de l'extérieur.

## Autorités : Let's Encrypt, staging, ZeroSSL, autre

- **Let's Encrypt** : le choix par défaut. Certificats de 90 jours (plus courts
  à l'avenir : le plugin s'adapte, voir le renouvellement). L'adresse e-mail
  est facultative.
- **Let's Encrypt staging** : le serveur de test. Ses certificats **ne sont
  reconnus par aucun navigateur**. Choisi comme autorité, il sert à vérifier
  la configuration de bout en bout ; le plugin refuse d'installer un tel
  certificat dans le serveur web. Le bouton **Tester (staging)** fait la même
  chose ponctuellement, quelle que soit l'autorité choisie, sans toucher au
  vrai certificat.
- **ZeroSSL** : exige une **adresse e-mail** (sur l'équipement ou dans la
  configuration du plugin) et un « External Account Binding » (EAB). Laissez
  les champs EAB **vides** : le plugin obtient les identifiants auprès de
  ZeroSSL à partir de l'adresse e-mail, puis les mémorise dans l'équipement.
  Vous pouvez aussi saisir ceux de votre tableau de bord ZeroSSL (*Developer →
  EAB Credentials*).
- **Autre autorité ACME** : saisissez l'URL de l'annuaire (`https://…/directory`)
  et, si elle l'exige, les identifiants EAB qu'elle fournit.

## Installation dans le serveur web

Cochez **Installer automatiquement dans le serveur web de Jeedom** : après
chaque émission ou renouvellement, le plugin

1. copie le certificat et la clé dans `/etc/ssl/jeedom-acme/` (clé en `0600`) :
   le serveur web ne dépend jamais du dossier du plugin ;
2. sauvegarde la configuration existante ;
3. écrit la configuration HTTPS (fichiers marqués « géré par le plugin Jeedom
   acme ») et active le module SSL si besoin ;
4. **teste la configuration** (`apachectl -t` / `nginx -t`) ;
5. recharge le serveur **en douceur** (graceful) : aucune connexion coupée.

Si le test échoue, **tout est restauré** et l'erreur est affichée : un serveur
qui fonctionnait continue de fonctionner. Les boutons **Installer dans le
serveur web** et **Désinstaller du serveur web** font la même chose à la
demande.

Options :

- **Port HTTPS** : 443 par défaut.
- **Rediriger HTTP vers HTTPS** : toute visite en `http://` part vers
  `https://`, sauf `/.well-known/acme-challenge/` (nécessaire au HTTP-01).
  **À n'activer qu'après avoir vérifié l'accès en `https://`.**
- **Port HTTPS public** : à remplir si votre routeur publie Jeedom sur un autre
  port que le port HTTPS local, par exemple **port public 9003 → Jeedom:443**
  pour éviter d'exposer le 443, très scanné. La redirection envoie alors vers
  `https://<votre nom>:9003`. Vide : même port que le port HTTPS.

  Exemple avec Home Assistant sur la même box : port public 9000 → HA:8123,
  9002 → Jeedom:80 (HTTP), 9003 → Jeedom:443 (HTTPS). Les deux certificats
  portent le même nom sans se gêner : un certificat est lié au nom, pas au port.

L'ordre recommandé :

1. installez (bouton **Installer dans le serveur web**, ou installation
   automatique cochée avant **Obtenir le certificat**) ;
2. ouvrez `https://<votre nom>` et vérifiez qu'il n'y a aucune alerte ;
3. **seulement alors**, cochez **Rediriger HTTP vers HTTPS**, sauvegardez et
   réinstallez.

> Gardez toujours un moyen d'accéder à Jeedom en `http://` par son adresse IP
> locale tant que l'HTTPS n'est pas vérifié. Le nom certifié doit résoudre vers
> l'adresse IP locale de Jeedom depuis votre navigateur : DNS local (routeur,
> Pi-hole…), enregistrement A public vers l'adresse privée, ou NAT loopback du
> routeur (voir [Principe](#principe)) ; à défaut, le fichier `hosts` du poste.
> Sinon le navigateur ne trouvera pas Jeedom, ou signalera une erreur de nom.

Le serveur web n'a **qu'une seule configuration HTTPS** pour tout Jeedom : un
seul certificat peut y être installé à la fois, et **Désinstaller du serveur
web** retire le HTTPS de Jeedom quel que soit l'équipement d'où on le fait.

Le bouton **Analyser le système**, dans la configuration du plugin, indique si
l'installation automatique est possible et pourquoi.

### Compatibilité

| Plateforme | Émission (DNS-01 / HTTP-01) | Installation auto HTTPS |
|---|---|---|
| Debian / Raspberry Pi OS / Ubuntu + Apache (installation Jeedom officielle, Smart, Luna, Atlas) | oui | oui |
| Docker (image officielle Jeedom, Apache) | oui | oui (sans systemd : `apachectl -k graceful`), à condition de publier le port 443 |
| RHEL / Fedora / Alma / Rocky + Apache | oui | oui si `mod_ssl` est installé |
| Alpine + Apache | oui | oui si `apache2-ssl` est installé |
| nginx | oui | semi-automatique : fichier de configuration généré, inclusion à faire à la main |
| Autre / sans droits root | oui | non : les fichiers PEM sont téléchargeables et utilisables ailleurs (proxy inverse, NAS…) |

L'installation passe par `sudo` (le compte `www-data` d'une installation
Jeedom en dispose sans mot de passe).

### Utiliser le certificat ailleurs

Les boutons **Télécharger fullchain** et **Télécharger la clé** donnent les
fichiers PEM (réservés aux administrateurs ; chaque téléchargement de clé est
tracé dans le journal). Ils conviennent à un proxy inverse (nginx, HAProxy,
Traefik), un NAS, une box… Pensez qu'il faudra les recopier à chaque
renouvellement.

## Docker

- L'émission fonctionne sans réglage particulier.
- Pour l'installation automatique, le conteneur doit **publier le port HTTPS** :
  `-p 443:443` (ou le port choisi) dans `docker run`, ou `ports: ["443:443"]`
  dans `docker-compose.yml`. Sans cela, Apache écoute en HTTPS dans le
  conteneur mais personne ne peut le joindre.
- Sans systemd, le rechargement se fait par `apachectl -k graceful`.
- La configuration Apache vit dans le conteneur : si celui-ci est recréé à
  partir de l'image, relancez **Installer dans le serveur web** (le certificat,
  lui, est conservé dans le dossier du plugin s'il est sur un volume).

## nginx

Le plugin génère le fichier de configuration HTTPS et copie les certificats,
mais **n'inclut pas** ce fichier dans votre configuration nginx : chaque
installation nginx est organisée différemment. Le chemin du fragment généré
et la marche à suivre sont indiqués dans le journal de la tâche : ajoutez
`include <fragment>;` dans un bloc `server { listen 443 ssl; server_name
<domaine>; … }` qui sert Jeedom, puis testez avec `nginx -t` et rechargez avec
`systemctl reload nginx`. Si le fragment est déjà inclus, le plugin se contente
de recharger nginx. Avant « Désinstaller du serveur web », retirez cet
`include`.

> **Obligatoire : interdire l'accès web à `plugins/acme/data/`.** nginx ignore
> les fichiers `.htaccess` : sans règle explicite, les clés privées rangées dans
> `data/` seraient téléchargeables par n'importe qui. Le fragment généré
> contient la règle ; mais **chaque** bloc `server` qui sert Jeedom, y compris
> celui du port 80, doit la porter :
>
> ```nginx
> location ^~ /plugins/acme/data/ { deny all; }
> ```
>
> Vérifiez ensuite que `http://<jeedom>/plugins/acme/data/` répond `403`.

## Renouvellement et alertes

- **Chaque jour**, le plugin met à jour les commandes de chaque équipement
  actif et vérifie l'échéance.
- Le renouvellement a lieu au **dernier tiers de la durée de vie** du
  certificat (30 jours avant la fin pour un certificat de 90 jours), ou
  **N jours avant l'expiration** si vous remplissez « Renouveler ». Un
  changement de la liste des domaines ou de l'autorité déclenche aussi une
  nouvelle émission.
- Le renouvellement part en tâche de fond, avec un **délai aléatoire** (de une
  minute à une heure, décalé de dix minutes par certificat) pour ne pas
  solliciter l'autorité à heure fixe.
- Si l'installation automatique est cochée, le nouveau certificat est
  réinstallé dans le serveur web.
- **Contrôle du certificat réellement servi.** Le plugin sait ce qu'il a
  installé, mais pas forcément ce que le serveur web répond (autre site
  configuré sur le même port, configuration restaurée, serveur pas rechargé).
  Chaque jour, après chaque installation, et à chaque enregistrement de
  l'équipement, il se connecte donc en HTTPS à `127.0.0.1` sur le port HTTPS
  local, en annonçant le nom principal, et compare le numéro de série du
  certificat présenté à celui du certificat en place. Le résultat est affiché
  sur la page (« Certificat servi par le serveur web ») et dans la commande
  « Certificat servi ». Ce contrôle n'a lieu que si le certificat est censé
  être servi (installation automatique cochée, ou installation faite par le
  bouton). S'il échoue — autre certificat présenté, ou serveur injoignable —
  le plugin écrit un avertissement dans le journal, un message dans le centre
  de messages, déclenche les notifications « Échec d'installation dans le
  serveur web », et relance l'installation (sauf sous nginx en mode manuel, où
  l'inclusion reste à faire à la main).
- En cas d'échec, l'erreur est gardée dans la commande « Dernière erreur » et
  le statut passe à `error`.
- Si le certificat expire dans moins de **14 jours** (« Alerter avant
  l'expiration », dans la configuration du plugin) sans avoir été renouvelé,
  quelle qu'en soit la raison, une alerte part **chaque jour** jusqu'au
  renouvellement : message dans le centre de messages de Jeedom, et actions de
  l'onglet Notifications.

> **Let's Encrypt n'envoie plus d'e-mails d'expiration depuis 2025.** C'est le
> plugin qui vous prévient : configurez au moins une action dans l'onglet
> Notifications.

### Notifications (mail, Telegram, SMS…)

L'onglet **Notifications** de l'équipement liste les actions à exécuter, comme
un bloc action de scénario :

1. **Ajouter une action**, puis choisir une commande avec le bouton
   <i class="fas fa-list-alt"></i> (par exemple la commande d'envoi de votre
   plugin Mail, Telegram, SMS, ou de l'application mobile), ou un bloc avec le
   bouton <i class="fas fa-tasks"></i> (lancer un scénario, régler une
   variable…).
2. Remplir les options (titre, message…) ou les laisser vides : un titre et
   un message clairs sont alors écrits par le plugin.
3. Cocher les **événements** qui déclenchent l'action :

   | Événement | Quand | Coché par défaut |
   |---|---|---|
   | Expiration proche | chaque jour, sous le seuil d'alerte, tant que le certificat n'est pas renouvelé | oui |
   | Échec d'obtention ou de renouvellement | à chaque échec (pas pour les essais sur le staging) | oui |
   | Échec d'installation dans le serveur web | à chaque échec | oui |
   | Certificat obtenu ou renouvelé | à chaque réussite | non |

4. **Sauvegarder**, puis **Tester les notifications** : toutes les actions
   enregistrées sont exécutées avec un message d'essai, quels que soient les
   événements cochés, et le résultat de chacune est affiché.

Étiquettes utilisables dans les options : `#equipement#`, `#domaines#`,
`#jours#` (jours restants), `#expiration#`, `#evenement#`, `#message#` (le
détail : erreur, date…). Exemple de message :
`#evenement# pour #domaines# : #message#`.

Une notification en échec (commande supprimée, service de mail en panne) est
écrite dans le journal `acme`.

### Page Santé

La page **Analyse → Santé** de Jeedom affiche une section ACME :

- une ligne par équipement actif : état (OK, à renouveler, expiré, erreur),
  jours restants, date du prochain renouvellement, dernière erreur, et
  certificat servi par le serveur web (résultat du dernier contrôle, sans
  nouvelle connexion à l'affichage) ;
- la **tâche quotidienne** : moteur de tâches de Jeedom actif, tâche
  `plugin::cronDaily` active, et fonctionnalité cronDaily du plugin active
  (Plugins → Gestion des plugins → ACME). Sans elle, rien n'est renouvelé ;
- les **droits sudo**, si un équipement installe son certificat dans le
  serveur web.

## Commandes

| Commande | Type | Contenu |
|---|---|---|
| Statut | info | `none` (aucun certificat), `valid`, `renew_soon` (renouvellement dû), `expired`, `error` (dernière émission ou dernier renouvellement en échec) |
| Expiration | info | date d'expiration, `AAAA-MM-JJ HH:MM` |
| Jours restants | info numérique | jours avant l'expiration, historisée |
| Prochain renouvellement | info | date prévue du prochain renouvellement, `AAAA-MM-JJ` ; vide sans certificat |
| Émetteur | info | autorité intermédiaire qui a signé le certificat |
| Dernier renouvellement | info | date de la dernière émission réussie |
| Certificat servi | info binaire | 1 si le serveur web sert bien ce certificat, 0 sinon (autre certificat, ou serveur injoignable) ; laissée vide si le certificat n'est pas censé être installé |
| Dernière erreur | info | message de la dernière erreur, vide si tout va bien |
| Renouveler | action | force un renouvellement immédiat (tâche de fond) |
| Installer dans le serveur web | action | réinstalle le certificat en place dans le serveur web |

Exemple de scénario : déclencheur `#[Maison][Certificat][Jours restants]# < 10`,
action : notification sur le téléphone. Autre exemple : déclencheur
`#[Maison][Certificat][Certificat servi]# == 0`.

Les commandes ajoutées par une mise à jour du plugin sont créées sur les
équipements existants à la mise à jour (ou au prochain enregistrement de
l'équipement), à leur place dans la liste si vous n'avez pas réordonné les
commandes, sinon à la fin.

## Désinstallation propre

Désactiver ou supprimer le plugin **ne retire pas** la configuration HTTPS du
serveur web : la retirer sans prévenir couperait peut-être l'accès par lequel
vous êtes en train de naviguer. Apache continue alors de servir le dernier
certificat installé (copié dans `/etc/ssl/jeedom-acme/`)… jusqu'à son
expiration, sans plus de renouvellement.

Pour tout retirer proprement :

1. Si la redirection HTTP → HTTPS est active, rouvrez Jeedom en `http://` par
   son adresse IP locale (la redirection disparaîtra avec la configuration).
2. Sur la fiche du certificat : **Désinstaller du serveur web**. La
   configuration ajoutée par le plugin est retirée, le serveur testé et
   rechargé.
3. Supprimez l'équipement (ses clés sont effacées), puis le plugin.

## Dépannage

- **La tâche échoue** : lisez le cadre « Tâche en cours », puis le journal
  complet **acme** (Analyse → Logs), en mode *Debug* pour le détail (niveau
  réglable dans la configuration du plugin). Les secrets n'y apparaissent
  jamais en clair.
- **L'enregistrement de l'équipement ne fait rien**, ou une page reste
  blanche : regardez `/var/www/html/log/http.error` avant toute autre
  hypothèse.
- **Limites de taux de Let's Encrypt** : 5 certificats identiques (mêmes
  noms) par semaine, et un nombre limité d'échecs de validation par heure.
  Faites vos essais avec **Tester (staging)**, qui n'est pas soumis à ces
  limites, et n'utilisez « Renouveler maintenant » qu'à bon escient. En cas
  de dépassement, l'erreur l'indique avec l'heure de fin du blocage.
- **DNS-01 : « enregistrement TXT jamais visible »** : le plugin s'est arrêté
  avant de solliciter l'autorité, aucune tentative n'est perdue. Augmentez
  l'attente de propagation (300 s par défaut) ; vérifiez que la zone est bien servie par les serveurs DNS
  d'OVH (et non par d'autres serveurs déclarés chez le registre) ; vérifiez
  qu'aucun enregistrement CNAME ne masque `_acme-challenge`.
- **DNS-01 : « 403 » ou « This call has not been granted »** : le jeton n'a pas
  les droits `GET/POST/DELETE /domain/zone/*`, ou il a expiré. Créez-en un
  nouveau.
- **HTTP-01 : « Connection refused » / « Timeout during connect »** : le port 80
  public n'arrive pas à Jeedom. Revoyez la redirection du routeur (80 → 80,
  pas 9002 → 80) et le pare-feu de la box.
- **HTTP-01 : « 404 »** : un autre serveur répond sur le port 80, ou la racine
  web n'est pas la bonne.
- **« Installation dans le serveur web en échec »** alors que le certificat est
  valide : l'émission a réussi, seule l'installation a échoué. Corrigez la
  cause, puis **Installer dans le serveur web** ; inutile de redemander un
  certificat.
- **Installation refusée** : le message reprend la sortie du script
  (`apachectl -t` en échec, module SSL absent, `sudo` indisponible…).
  **Analyser le système** dans la configuration du plugin résume ce qui
  manque.
- **Le navigateur signale un nom incorrect** : vous accédez à Jeedom par une
  adresse IP ou un autre nom que celui du certificat.
- **`https://<nom>` ne répond pas depuis la maison** : le nom ne résout pas
  vers l'adresse locale de Jeedom. Voir le rappel réseau dans
  [Principe](#principe) (DNS local, enregistrement A vers l'adresse privée ou
  NAT loopback).

## FAQ

**Puis-je certifier `jeedom.local` ?**
Non. Aucune autorité publique ne certifie un nom privé. Utilisez un
sous-domaine d'un domaine qui vous appartient ; en DNS-01, il peut désigner
une adresse locale.

**Faut-il ouvrir un port ?**
En DNS-01, aucun. En HTTP-01, le port public 80 vers Jeedom:80, et uniquement
celui-là.

**Mon accès distant passe par le port 9002 : HTTP-01 va-t-il marcher ?**
Non : l'autorité ne se connecte qu'au port 80. Utilisez DNS-01.

**Puis-je avoir un certificat `*.mondomaine.fr` ?**
Oui, en DNS-01. Mettez aussi `mondomaine.fr` dans la liste si vous voulez
couvrir le nom nu : un générique ne le couvre pas.

**Plusieurs certificats ?**
Oui : un équipement par certificat. Un seul peut être installé dans le serveur
web de Jeedom ; les autres servent par téléchargement.

**Où sont les clés ?**
Dans `plugins/acme/data/` (accès web refusé, droits `0700`/`0600`), et, pour le
certificat installé, dans `/etc/ssl/jeedom-acme/`. La clé du compte ACME n'est
jamais téléchargeable.

**Le plugin utilise-t-il certbot ou acme.sh ?**
Non. Le protocole ACME est implémenté en PHP, sans dépendance.

**Que se passe-t-il si Jeedom est éteint le jour du renouvellement ?**
Rien de grave : le renouvellement commence 30 jours avant l'expiration et est
retenté chaque jour.

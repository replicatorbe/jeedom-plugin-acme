# Changelog

## 0.1

Première version.

- Un équipement par certificat : un ou plusieurs domaines, le premier étant le
  nom principal ; certificats génériques (`*.domaine`) en DNS-01.
- Autorités : Let's Encrypt, Let's Encrypt staging, ZeroSSL (identifiants EAB
  obtenus automatiquement à partir de l'adresse e-mail), ou toute autorité ACME
  par l'URL de son annuaire, avec EAB si elle l'exige.
- Validation DNS-01 par l'API OVHcloud (tous les points d'accès OVH, Kimsufi et
  So you Start), avec lien de création d'un jeton aux droits restreints et
  bouton de test des accès placé juste après le choix du point d'accès ;
  vérification de la propagation directement auprès des serveurs DNS faisant
  autorité, repli DNS-over-HTTPS. Délai de propagation réglable (300 s par
  défaut) : s'il est dépassé, le plugin s'arrête sans solliciter l'autorité, et
  donc sans consommer de tentative Let's Encrypt.
- Validation HTTP-01 dans la racine web de Jeedom.
- Bouton « Tester (staging) » : émission complète sur le serveur de test de
  Let's Encrypt, sans limite de taux et sans rien installer.
- Émission en tâche de fond, avec suivi de l'étape en cours et des dernières
  lignes du journal sur la page de l'équipement ; le suivi résiste aux
  coupures passagères (nouvel essai toutes les 5 s, abandon après 10 échecs).
- Échec d'émission et échec d'installation dans le serveur web affichés
  séparément.
- Installation dans le serveur web (Apache ; nginx en semi-automatique) :
  sauvegarde, test de configuration, rechargement en douceur et retour arrière
  automatique ; redirection HTTP → HTTPS en option ; analyse de compatibilité
  du système depuis la configuration du plugin. Sous nginx, accès web à
  `plugins/acme/data/` interdit par le fragment généré
  (`location ^~ /plugins/acme/data/ { deny all; }`), à reporter dans chaque
  bloc `server` qui sert Jeedom.
- Renouvellement automatique quotidien au dernier tiers de la durée de vie (ou
  N jours avant l'expiration), étalé dans le temps ; alerte quotidienne dans le
  centre de messages si l'échéance approche sans renouvellement.
- Port HTTPS public (ex. 9003 → Jeedom:443) : cible de la redirection HTTP →
  HTTPS quand le routeur publie Jeedom sur un autre port.
- Onglet Notifications : actions au choix (mail, Telegram, SMS, scénario…)
  déclenchées par l'expiration proche, un échec d'émission, un échec
  d'installation ou un renouvellement réussi, avec étiquettes (#domaines#,
  #jours#, #message#…) et bouton « Tester les notifications ».
- Commandes : statut, expiration, jours restants (historisée), prochain
  renouvellement, émetteur, dernier renouvellement, certificat servi,
  dernière erreur ; actions Renouveler et Installer dans le serveur web.
- Contrôle du certificat réellement servi par le serveur web (sonde TLS
  locale avec SNI, comparaison du numéro de série) : chaque jour, après chaque
  installation et à chaque enregistrement ; en cas d'écart ou de serveur
  injoignable, avertissement, message, notification et nouvelle installation.
- Page Santé : une ligne par certificat (état, jours restants, prochain
  renouvellement, dernière erreur, certificat servi), la tâche quotidienne de
  Jeedom et les droits sudo.
- Téléchargement des fichiers PEM (fullchain, clé, certificat, chaîne), réservé
  aux administrateurs.
- Parcours guidé sur la page : essai, émission, installation, vérification de
  `https://`, puis redirection ; rappel sur la résolution du nom depuis le
  réseau local (DNS local, enregistrement A vers l'adresse privée, NAT
  loopback).
- Interface traduite en anglais, champs du fournisseur DNS compris.
- Aucune dépendance : PHP seul (extensions openssl, curl, json).

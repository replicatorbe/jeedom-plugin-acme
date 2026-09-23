<?php
/* Contrôles par réflexion contre le coeur de Jeedom installé.
 *
 *   php tests/check-classes.php
 *
 * Ces pièges ont ceci de commun qu'ils sont invisibles à la relecture,
 * invisibles à « php -l », et invisibles au jeu d'essai hors ligne : ils ne se
 * manifestent que dans un vrai Jeedom, et leur symptôme ne ressemble pas à leur
 * cause. Tous trois se vérifient en quelques lignes de réflexion. */

$core = '/var/www/html/core/php/core.inc.php';
if (!is_readable($core)) {
    echo "Jeedom introuvable : contrôle ignoré.\n";
    exit(0);
}
require_once $core;

$file = __DIR__ . '/../core/class/acme.class.php';
$source = file_get_contents($file);
$problems = array();

/* ------------------------------------------------------------------ 1 ---
 * Toute propriété d'une classe eqLogic ou cmd doit commencer par un souligné.
 * DB::save() traite les autres comme des colonnes de la table : une propriété
 * « $refreshError » fait échouer la création d'un équipement sur « Unknown
 * column », sans que le journal du plugin en dise un mot. */
preg_match_all('/^\s*(?:private|protected|public)\s+(?!static|function)\$(\w+)/m', $source, $m);
foreach ($m[1] as $name) {
    if (strpos($name, '_') !== 0) {
        $problems[] = 'Propriété sans souligné initial : $' . $name
            . ' — DB::save() la prendra pour une colonne de la table.';
    }
}

/* ------------------------------------------------------------------ 2 ---
 * Aucune méthode ne doit s'appeler « set » suivi d'une clé du formulaire, et
 * surtout pas setCmd(). À l'enregistrement, utils::a2o() appelle « set » + clé
 * pour chaque clé reçue, et la page envoie toujours une clé « cmd » : une
 * méthode privée de ce nom tue la sauvegarde sur une erreur fatale, avant toute
 * écriture. La page se rafraîchit, la saisie disparaît, le journal reste muet. */
$forbidden = array('setId', 'setName', 'setLogicalId', 'setGeneric_type', 'setObject_id',
                   'setEqType_name', 'setIsVisible', 'setIsEnable', 'setConfiguration',
                   'setTimeout', 'setCategory', 'setDisplay', 'setOrder', 'setComment',
                   'setTags', 'setCmd');
foreach ($forbidden as $name) {
    if (preg_match('/function\s+' . $name . '\s*\(/i', $source)) {
        $problems[] = 'Méthode interdite : ' . $name . '() — utils::a2o() l\'appellera à '
            . 'chaque enregistrement et tuera la sauvegarde.';
    }
}

/* ------------------------------------------------------------------ 3 ---
 * Une méthode héritée ne peut pas voir sa visibilité réduite. eqLogic et cmd
 * exposent publiquement getCache(), setCache(), getStatus(), setStatus() et bien
 * d'autres : les redéclarer en privé est une erreur fatale AU CHARGEMENT de la
 * classe. Or le coeur charge la classe de chaque plugin actif sur chaque page —
 * toute l'interface de Jeedom tombe alors en HTTP 500, pas seulement le plugin.
 * C'est arrivé, sur getCache() et setCache(). */
preg_match_all('/^\s*(private|protected|public)\s+(?:static\s+)?function\s+(\w+)/m', $source, $m, PREG_SET_ORDER);
$rank = array('private' => 0, 'protected' => 1, 'public' => 2);
foreach (array('eqLogic', 'cmd') as $parent) {
    $ref = new ReflectionClass($parent);
    foreach ($m as $declaration) {
        $visibility = $declaration[1];
        $name = $declaration[2];
        if (!$ref->hasMethod($name)) {
            continue;
        }
        $inherited = $ref->getMethod($name);
        $parentVisibility = $inherited->isPrivate() ? 'private'
            : ($inherited->isProtected() ? 'protected' : 'public');
        if ($rank[$visibility] < $rank[$parentVisibility]) {
            $problems[] = 'Visibilité réduite sur une méthode héritée : ' . $name . '() est '
                . $visibility . ' ici et ' . $parentVisibility . ' dans ' . $parent
                . ' — erreur fatale au chargement, Jeedom entier en HTTP 500.';
        }
    }
}

/* ------------------------------------------------------------------ 4 ---
 * La classe de commande est obligatoire, même vide : core/ajax/eqLogic.ajax.php
 * refuse de créer ou d'ouvrir un équipement si elle manque. */
if (!preg_match('/class\s+acmeCmd\s+extends\s+cmd/', $source)) {
    $problems[] = 'Classe acmeCmd absente — impossible de créer un équipement.';
}

/* ------------------------------------------------------------------ 5 ---
 * Les points d'entrée que le coeur appelle sur la CLASSE et non sur un objet
 * doivent être déclarés static.
 *
 * desktop/php/health.php teste method_exists() puis appelle <plugin>::health()
 * en statique : une méthode d'instance passe le test et lève une Error à
 * l'appel. Or le coeur l'entoure d'un catch (Exception), qui n'attrape pas les
 * Error de PHP 8. Ce n'est donc pas le plugin qui tombe, mais la page Santé de
 * toute l'installation, en HTTP 500. Le même raisonnement vaut pour les crons
 * et pour le trio du démon, appelés de la même façon.
 *
 * C'est arrivé, sur health(). */
$staticHooks = array('health', 'cron', 'cron5', 'cron10', 'cron15', 'cron30',
                     'cronHourly', 'cronDaily', 'deamon_info', 'deamon_start',
                     'deamon_stop', 'deamon_changeAutoMode', 'dependancy_info',
                     'dependancy_install', 'templateWidget', 'pull');
/* config::save appelle <plugin>::preConfig_<clé>() et postConfig_<clé>() sur la
 * classe : même exigence. */
preg_match_all('/function\s+((?:pre|post)Config_\w+)\s*\(/', $source, $configHooks);
$staticHooks = array_merge($staticHooks, $configHooks[1]);
foreach ($staticHooks as $hook) {
    if (preg_match('/^\s*(private|protected|public)(\s+static)?\s+function\s+' . $hook . '\s*\(/mi', $source, $m)) {
        if (!isset($m[2]) || trim($m[2]) === '') {
            $problems[] = 'Point d\'entrée non statique : ' . $hook . '() — le coeur l\'appelle sur la classe, '
                . 'l\'Error qui en résulte n\'est pas rattrapée et emporte la page qui l\'invoque.';
        }
        if (isset($m[1]) && $m[1] !== 'public') {
            $problems[] = 'Point d\'entrée non public : ' . $hook . '() — le coeur ne pourra pas l\'appeler.';
        }
    }
}

/* ------------------------------------------------------------------ 6 ---
 * Propre à acme : .deployignore doit exclure data/ (clés privées produites à
 * l'exécution) et tests/. Sans data/, la synchronisation à l'identique de
 * deploy-plugin.sh effacerait les clés du compte ACME et des certificats à
 * chaque déploiement. */
$deployignore = @file_get_contents(__DIR__ . '/../.deployignore');
foreach (array('data/', 'tests/') as $pattern) {
    if ($deployignore === false || !preg_match('#^' . preg_quote($pattern, '#') . '\s*$#m', $deployignore)) {
        $problems[] = '.deployignore n\'exclut pas ' . $pattern
            . ($pattern === 'data/' ? ' — chaque déploiement effacerait les clés privées.' : '.');
    }
}

/* ------------------------------------------------------------------ 7 ---
 * Propre à acme : la classe se charge réellement, avec les bibliothèques
 * qu'elle inclut (acmeCrypto, acmeClient, acmeSolver, acmeDns, acmeDnsOvh,
 * acmeInstaller). Une erreur ici tuerait toutes les pages de Jeedom : le coeur
 * charge la classe de chaque plugin actif. */
try {
    require_once $file;
    foreach (array('acme', 'acmeCmd', 'acmeCrypto', 'acmeClient', 'acmeException', 'acmeSolver',
                   'acmeSolverHttp', 'acmeSolverDns', 'acmeDns', 'acmeDnsCheck', 'acmeDnsOvh',
                   'acmeInstaller') as $class) {
        if (!class_exists($class, false)) {
            $problems[] = 'Classe ' . $class . ' absente après chargement de acme.class.php.';
        }
    }
    if (!interface_exists('acmeDnsProvider', false)) {
        $problems[] = 'Interface acmeDnsProvider absente après chargement de acme.class.php.';
    }
    foreach (array('runIssue', 'runInstall', 'runUninstall', 'getCertificateInfo', 'refreshInfo',
                   'isRenewalDue', 'launchJob', 'getJobStatus', 'executeJob') as $method) {
        if (class_exists('acme', false) && !method_exists('acme', $method)) {
            $problems[] = 'Méthode acme::' . $method . '() absente.';
        }
    }
} catch (Throwable $e) {
    $problems[] = 'Chargement de acme.class.php impossible : ' . $e->getMessage();
}

/* ---------------------------------------------------------------- BILAN --- */
if (empty($problems)) {
    echo "Contrôles du coeur : aucun problème.\n";
    exit(0);
}
echo "Contrôles du coeur : " . count($problems) . " problème(s)\n";
foreach ($problems as $problem) {
    echo '  - ' . $problem . "\n";
}
exit(1);

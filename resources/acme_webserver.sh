#!/bin/sh
# Installation d'un certificat TLS dans le serveur web local — plugin Jeedom acme.
#
# Auteur : sMug (Jérôme Fafchamps) — licence AGPL.
#
# Script POSIX (dash, ash de busybox, bash en mode sh) : aucun bashisme, aucune
# instruction « local ». Il est lancé en root, via sudo quand Jeedom en dispose :
#
#   acme_webserver.sh detect
#   acme_webserver.sh install --domain D --fullchain F --key K [--alias NOM]…
#                             [--port 443] [--redirect 0|1] [--redirect-port N]
#                             [--webroot /var/www/html] [--force-port]
#
# --redirect-port : port HTTPS vu depuis Internet, cible de la redirection
# HTTP → HTTPS, quand le routeur publie Jeedom sur un autre port que --port
# (ex. port public 9003 → Jeedom:443). Par défaut : --port.
#   acme_webserver.sh reload
#   acme_webserver.sh uninstall
#   acme_webserver.sh status
#
# Sortie : des lignes « cle=valeur » sur la sortie standard, analysables par
# acmeInstaller ; les messages lisibles vont sur la sortie d'erreur.
#
# Principe : ne jamais casser un serveur qui marche. Chaque fichier touché est
# sauvegardé, l'état des modules et sites activés est relevé, la configuration
# est testée (apachectl -t) AVANT le rechargement, et tout est restauré si le
# test échoue. Le rechargement est toujours « en douceur » (graceful).
#
# Fichiers gérés (tous portent le marqueur « géré par le plugin Jeedom acme ») :
#   /etc/ssl/jeedom-acme/<domaine>/fullchain.pem (0644) et privkey.pem (0600)
#   Debian  : /etc/apache2/sites-available/jeedom-acme-ssl.conf (a2ensite)
#             /etc/apache2/conf-available/jeedom-acme-redirect.conf (a2enconf)
#   RHEL    : /etc/httpd/conf.d/jeedom-acme-ssl.conf, jeedom-acme-redirect.conf
#   SUSE    : /etc/apache2/vhosts.d/jeedom-acme-ssl.conf, conf.d/jeedom-acme-redirect.conf
#   Alpine  : /etc/apache2/conf.d/jeedom-acme-ssl.conf, jeedom-acme-redirect.conf
#   nginx   : /etc/nginx/snippets/jeedom-acme-ssl.conf (inclusion manuelle)
# Aucun fichier existant du système n'est modifié (000-default.conf compris).
#
# Variables d'environnement :
#   ACME_ROOT    préfixe de tous les chemins (arborescence factice pour les
#                essais). Dans ce mode, les commandes système réelles
#                (/usr, /bin, /sbin) qui modifient quelque chose ne sont jamais
#                lancées : seules des commandes placées hors de ces dossiers
#                (faux binaires en tête du PATH) le sont.
#   ACME_DRYRUN  1 = simulation : rien n'est écrit ni lancé, le contenu qui
#                serait écrit est affiché sur la sortie d'erreur.
#   ACME_RELOAD_WAIT  secondes d'attente avant de vérifier qu'Apache tourne
#                encore après un rechargement (3 par défaut, 0 avec ACME_ROOT).
#
# Noms : --domain est le nom principal (ServerName, dossier du certificat).
# Il peut être un joker « *.exemple.fr » : ServerName vaut alors « exemple.fr »,
# mais ce nom nu n'est considéré comme couvert que s'il est aussi passé en
# --alias. Chaque --alias (répétable, jokers « *.x » acceptés) donne une
# directive ServerAlias. La redirection HTTP → HTTPS ne vise que les noms
# couverts : le nom principal (s'il n'est pas un joker, ou chaque sous-domaine
# d'un joker) et les alias.
#
# Codes de retour :
#   0   succès (y compris nginx en mode manuel, et « rien à faire »)
#   1   erreur inattendue
#   2   arguments invalides (domaine, chemin, port, PEM, clé ≠ certificat)
#   3   droits root nécessaires
#   4   plateforme non prise en charge (serveur web ou dossier de conf introuvable)
#   5   module TLS absent (mod_ssl à installer)
#   6   test de configuration en échec après modification : tout a été restauré
#   7   configuration valide mais rechargement du serveur web en échec
#   8   test de configuration déjà en échec AVANT toute modification : rien fait
#   9   restauration incomplète après un échec (intervention manuelle nécessaire)
#   10  port déjà utilisé : par un autre programme que le serveur web, ou par
#       un VirtualHost HTTP (sans SSLEngine on) d'Apache
#   11  Apache arrêté (port pris, etc.) ou n'écoutant pas le port HTTPS après
#       le rechargement : l'état précédent a été restauré et Apache relancé
#   12  impossible de vérifier que le port est libre (ni ss ni netstat) alors
#       qu'un Listen doit être ajouté : refusé, sauf --force-port

set -u
umask 022

MARKER='géré par le plugin Jeedom acme'
SCRIPT_PATH="$0"
R="${ACME_ROOT:-}"
R="${R%/}"
DRY="${ACME_DRYRUN:-0}"
[ "$DRY" = "1" ] || DRY=0

# Les outils d'administration sont souvent dans sbin, absent du PATH de
# www-data : on l'ajoute EN FIN de PATH, pour que de faux binaires placés en
# tête (essais) restent prioritaires.
for acme_p in /usr/local/sbin /usr/sbin /sbin /usr/local/bin /usr/bin /bin; do
    case ":$PATH:" in
        *":$acme_p:"*) ;;
        *) PATH="$PATH:$acme_p" ;;
    esac
done
export PATH

SSL_CONF_NAME='jeedom-acme-ssl'
REDIR_CONF_NAME='jeedom-acme-redirect'
CERT_ROOT_L='/etc/ssl/jeedom-acme'          # chemin logique (vu par le serveur web)
CERT_ROOT="$R$CERT_ROOT_L"                  # chemin réel (préfixé par ACME_ROOT)
BACKUP_ROOT="$R/var/backups/jeedom-acme"
BK_DIR=''
BK_N=0
SNAPSHOT_DONE=0
WEBSERVER=unknown

# ---------------------------------------------------------------------------
# Sorties
# ---------------------------------------------------------------------------

msg() {
    printf '%s\n' "$*" >&2
}

# out cle valeur : une ligne cle=valeur, retours à la ligne remplacés par des espaces.
out() {
    printf '%s=%s\n' "$1" "$(printf '%s' "$2" | tr '\n\r' '  ')"
}

# die code message : message d'erreur lisible + clés result/error, puis sortie.
die() {
    msg "ERREUR : $2"
    out result error
    out code "$1"
    out error "$2"
    exit "$1"
}

# ---------------------------------------------------------------------------
# Commandes : recherche et exécution protégée
# ---------------------------------------------------------------------------

# Vrai si le chemin désigne un binaire du système réel.
is_sys_bin() {
    case "$1" in
        /usr/*|/bin/*|/sbin/*|/lib/*|/opt/*) return 0 ;;
    esac
    return 1
}

# Outil en lecture seule (openssl…) : trouvé normalement.
tool_cmd() {
    command -v "$1" 2>/dev/null
}

# Commande qui agit sur le système ou dont le résultat dépend de la vraie
# machine (serveur web, a2enmod, systemctl, ss…). Avec ACME_ROOT, les binaires
# du système réel sont ignorés : l'arborescence factice ne doit rien voir ni
# rien toucher de la vraie machine.
srv_cmd() {
    sc_p=$(command -v "$1" 2>/dev/null) || return 1
    case "$sc_p" in
        /*) ;;
        *) return 1 ;;          # fonction ou alias : ignoré
    esac
    if [ -n "$R" ] && is_sys_bin "$sc_p"; then
        return 1
    fi
    printf '%s\n' "$sc_p"
}

# run_sys commande args… : lance une commande qui modifie le système.
# Sa sortie va sur stderr (stdout est réservé aux cle=valeur).
run_sys() {
    if [ "$DRY" = "1" ]; then
        msg "[simulation] $*"
        return 0
    fi
    if [ -n "$R" ] && is_sys_bin "$1"; then
        msg "[ACME_ROOT] commande système non lancée : $*"
        return 0
    fi
    "$@" >&2
}

# run_tool nom args… : comme run_sys, pour une commande cherchée par srv_cmd.
# Introuvable : ignorée avec ACME_ROOT ou en simulation, erreur sinon.
run_tool() {
    rt_name="$1"; shift
    if rt_p=$(srv_cmd "$rt_name"); then
        run_sys "$rt_p" "$@"
        return $?
    fi
    if [ "$DRY" = "1" ] || [ -n "$R" ]; then
        msg "[essai] $rt_name introuvable hors système : $rt_name $* non lancé"
        return 0
    fi
    msg "commande introuvable : $rt_name"
    return 1
}

# ---------------------------------------------------------------------------
# Écriture de fichiers
# ---------------------------------------------------------------------------

# write_file chemin mode : écrit l'entrée standard, de façon atomique.
write_file() {
    wf_dest="$1"; wf_mode="$2"
    if [ "$DRY" = "1" ]; then
        msg "[simulation] écriture de $wf_dest (mode $wf_mode) :"
        sed 's/^/  | /' >&2
        return 0
    fi
    mkdir -p "$(dirname "$wf_dest")" || return 1
    wf_tmp="$wf_dest.acme-tmp.$$"
    ( umask 077; cat > "$wf_tmp" ) || { rm -f "$wf_tmp"; return 1; }
    chmod "$wf_mode" "$wf_tmp" || { rm -f "$wf_tmp"; return 1; }
    if [ "$(id -u)" = "0" ]; then
        chown 0:0 "$wf_tmp" 2>/dev/null
    fi
    mv -f "$wf_tmp" "$wf_dest"
}

# ---------------------------------------------------------------------------
# Sauvegarde et restauration
# ---------------------------------------------------------------------------
# Le manifeste liste, dans l'ordre, l'état d'origine de chaque chemin touché :
#   F|chemin|n   fichier ordinaire, copie dans files/n
#   L|chemin|cible  lien symbolique
#   D|chemin|n   dossier, copie récursive dans files/n
#   N|chemin     n'existait pas
# La restauration le relit à l'envers.

bk_init() {
    [ -n "$BK_DIR" ] && return 0
    [ "$DRY" = "1" ] && return 0
    BK_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)-$$"
    ( umask 077; mkdir -p "$BK_DIR/files" ) || die 1 "impossible de créer le dossier de sauvegarde $BK_DIR"
    chmod 700 "$BACKUP_ROOT" "$BK_DIR" 2>/dev/null
    : > "$BK_DIR/manifest"
}

bk_path() {
    [ "$DRY" = "1" ] && return 0
    bk_init
    # déjà sauvegardé ? (on ne garde que l'état d'origine)
    if cut -d'|' -f2 "$BK_DIR/manifest" | grep -q -F -x -e "$1"; then
        return 0
    fi
    BK_N=$((BK_N + 1))
    if [ -L "$1" ]; then
        printf 'L|%s|%s\n' "$1" "$(readlink "$1")" >> "$BK_DIR/manifest"
    elif [ -d "$1" ]; then
        cp -Rp "$1" "$BK_DIR/files/$BK_N" || rollback_and_die 1 "sauvegarde impossible de $1"
        printf 'D|%s|%s\n' "$1" "$BK_N" >> "$BK_DIR/manifest"
    elif [ -e "$1" ]; then
        cp -p "$1" "$BK_DIR/files/$BK_N" || rollback_and_die 1 "sauvegarde impossible de $1"
        printf 'F|%s|%s\n' "$1" "$BK_N" >> "$BK_DIR/manifest"
    else
        printf 'N|%s\n' "$1" >> "$BK_DIR/manifest"
    fi
}

# Restaure tous les chemins du manifeste. Renvoie 1 si un élément résiste.
bk_restore() {
    [ -n "$BK_DIR" ] || return 0
    br_rc=0
    # ordre inverse, sans tac (non POSIX)
    br_list=$(sed -n '1!G;h;$p' "$BK_DIR/manifest")
    br_old_ifs="$IFS"
    IFS='
'
    for br_line in $br_list; do
        IFS="$br_old_ifs"
        br_type=$(printf '%s' "$br_line" | cut -d'|' -f1)
        br_path=$(printf '%s' "$br_line" | cut -d'|' -f2)
        br_arg=$(printf '%s' "$br_line" | cut -d'|' -f3-)
        case "$br_type" in
            N)
                rm -rf "$br_path" || br_rc=1 ;;
            L)
                rm -rf "$br_path"; ln -s "$br_arg" "$br_path" || br_rc=1 ;;
            F)
                rm -rf "$br_path"
                mkdir -p "$(dirname "$br_path")"
                cp -p "$BK_DIR/files/$br_arg" "$br_path" || br_rc=1 ;;
            D)
                rm -rf "$br_path"
                mkdir -p "$(dirname "$br_path")"
                cp -Rp "$BK_DIR/files/$br_arg" "$br_path" || br_rc=1 ;;
        esac
        IFS='
'
    done
    IFS="$br_old_ifs"
    return $br_rc
}

# Ne garde que les 5 sauvegardes les plus récentes (elles contiennent des clés).
bk_prune() {
    [ -d "$BACKUP_ROOT" ] || return 0
    bp_n=0
    for bp_d in $(ls -1 "$BACKUP_ROOT" 2>/dev/null | sort -r); do
        bp_n=$((bp_n + 1))
        [ $bp_n -gt 5 ] && rm -rf "${BACKUP_ROOT:?}/$bp_d"
    done
    return 0
}

# ---------------------------------------------------------------------------
# Détection
# ---------------------------------------------------------------------------

# Lit une clé de os-release sans exécuter le fichier.
osr_get() {
    sed -n "s/^$1=//p" "$OSR_FILE" 2>/dev/null | head -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# Vrai si un processus de ce nom tourne (lecture de /proc/*/comm).
proc_running() {
    for pr_f in "$R"/proc/[0-9]*/comm; do
        [ -r "$pr_f" ] || continue
        pr_c=$(cat "$pr_f" 2>/dev/null)
        for pr_n in "$@"; do
            [ "$pr_c" = "$pr_n" ] && return 0
        done
    done
    return 1
}

# Qui écoute sur le port TCP $1 ? Positionne PORT_USED (0|1|unknown) et PORT_OWNER.
port_probe() {
    PORT_USED=unknown; PORT_OWNER=''
    pp_out=''
    if pp_ss=$(srv_cmd ss); then
        pp_out=$("$pp_ss" -H -ltnp 2>/dev/null) || pp_out=$("$pp_ss" -ltnp 2>/dev/null | sed 1d)
        pp_lines=$(printf '%s\n' "$pp_out" | awk -v p=":$1" '{ n = split($4, a, ":"); if (":" a[n] == p) print }')
    elif pp_ns=$(srv_cmd netstat); then
        pp_out=$("$pp_ns" -ltnp 2>/dev/null)
        pp_lines=$(printf '%s\n' "$pp_out" | awk -v p=":$1" '$1 ~ /^tcp/ { n = split($4, a, ":"); if (":" a[n] == p) print }')
    else
        return 0
    fi
    if [ -z "$pp_lines" ]; then
        PORT_USED=0
        return 0
    fi
    PORT_USED=1
    PORT_OWNER=$(printf '%s\n' "$pp_lines" | sed -n -e 's/.*users:(("\([^"]*\)".*/\1/p' -e 's/.*[0-9]\/\([A-Za-z0-9_.-]*\).*/\1/p' | head -n 1)
    [ -n "$PORT_OWNER" ] || PORT_OWNER=unknown
    return 0
}

# Détecte tout et positionne les variables globales. N'écrit rien.
do_detect() {
    OSR_FILE="$R/etc/os-release"
    [ -r "$OSR_FILE" ] || OSR_FILE="$R/usr/lib/os-release"
    OS_ID=$(osr_get ID | tr '[:upper:]' '[:lower:]')
    OS_LIKE=$(osr_get ID_LIKE | tr '[:upper:]' '[:lower:]')
    OS_VERSION=$(osr_get VERSION_ID)
    OS_NAME=$(osr_get PRETTY_NAME)
    [ -n "$OS_ID" ] || OS_ID=unknown

    # Famille de distribution : d'abord ID, puis chaque mot de ID_LIKE.
    LAYOUT=generic
    for dd_w in $OS_ID $OS_LIKE; do
        case "$dd_w" in
            debian|ubuntu|raspbian|armbian|linuxmint|pop|devuan|kali|elementary|zorin)
                LAYOUT=debian ;;
            rhel|centos|fedora|rocky|almalinux|ol|amzn|scientific|eurolinux|circle)
                LAYOUT=rhel ;;
            suse|opensuse|opensuse-leap|opensuse-tumbleweed|sles|sled|sle-micro)
                LAYOUT=suse ;;
            alpine)
                LAYOUT=alpine ;;
            arch|manjaro|endeavouros|artix|garuda)
                LAYOUT=arch ;;
            *) continue ;;
        esac
        break
    done

    # Conteneur et système d'init
    DOCKER=0
    if [ -e "$R/.dockerenv" ] || [ -e "$R/run/.containerenv" ]; then
        DOCKER=1
    elif grep -q -E 'docker|kubepods|containerd|libpod' "$R/proc/1/cgroup" 2>/dev/null; then
        DOCKER=1
    fi
    SYSTEMD=0
    [ -d "$R/run/systemd/system" ] && SYSTEMD=1

    # Apache : binaire de contrôle
    APACHE_CTL=''
    case "$LAYOUT" in
        debian) dd_cands='apache2ctl apachectl' ;;
        *)      dd_cands='apachectl apache2ctl httpd' ;;
    esac
    for dd_c in $dd_cands; do
        if dd_p=$(srv_cmd "$dd_c"); then
            if [ "$dd_c" = httpd ]; then
                # busybox fournit aussi un « httpd » : on vérifie que c'est Apache.
                "$dd_p" -v 2>/dev/null | grep -q Apache || continue
            fi
            APACHE_CTL="$dd_p"
            break
        fi
    done
    APACHE_VERSION=''
    if [ -n "$APACHE_CTL" ]; then
        APACHE_VERSION=$("$APACHE_CTL" -v 2>/dev/null | sed -n 's/.*Apache\/\([0-9][0-9.]*\).*/\1/p' | head -n 1)
    fi
    APACHE_RUNNING=0
    proc_running apache2 httpd && APACHE_RUNNING=1
    NGINX_BIN=$(srv_cmd nginx) || NGINX_BIN=''
    NGINX_RUNNING=0
    proc_running nginx && NGINX_RUNNING=1

    WEBSERVER=unknown
    if [ -n "$APACHE_CTL" ] && [ -n "$NGINX_BIN" ]; then
        # les deux installés : celui qui tourne, Apache par défaut (Jeedom)
        if [ "$NGINX_RUNNING" = 1 ] && [ "$APACHE_RUNNING" = 0 ]; then
            WEBSERVER=nginx
        else
            WEBSERVER=apache
        fi
    elif [ -n "$APACHE_CTL" ]; then
        WEBSERVER=apache
    elif [ -n "$NGINX_BIN" ]; then
        WEBSERVER=nginx
    fi

    # Dossiers selon la famille
    AP_DIR=''; CONF_SSL_L=''; CONF_REDIR_L=''; LOG_DIR=''; SERVICE=''
    LOAD_SSL=''; SSL_MODULE=0; SSL_ENABLED=unknown; MISSING_HINT=''
    case "$LAYOUT" in
        debian)
            AP_DIR=/etc/apache2
            CONF_SSL_L="$AP_DIR/sites-available/$SSL_CONF_NAME.conf"
            CONF_REDIR_L="$AP_DIR/conf-available/$REDIR_CONF_NAME.conf"
            LOG_DIR='${APACHE_LOG_DIR}'
            SERVICE=apache2
            [ -f "$R$AP_DIR/mods-available/ssl.load" ] && SSL_MODULE=1
            SSL_ENABLED=0
            [ -e "$R$AP_DIR/mods-enabled/ssl.load" ] && SSL_ENABLED=1
            MISSING_HINT='apt install apache2'
            ;;
        rhel)
            AP_DIR=/etc/httpd
            CONF_SSL_L="$AP_DIR/conf.d/$SSL_CONF_NAME.conf"
            CONF_REDIR_L="$AP_DIR/conf.d/$REDIR_CONF_NAME.conf"
            LOG_DIR=logs
            SERVICE=httpd
            for dd_f in "$R$AP_DIR"/conf.modules.d/*ssl* "$R"/usr/lib64/httpd/modules/mod_ssl.so "$R"/usr/lib/httpd/modules/mod_ssl.so; do
                [ -e "$dd_f" ] && SSL_MODULE=1 && break
            done
            SSL_ENABLED=$SSL_MODULE
            MISSING_HINT='dnf install mod_ssl'
            ;;
        suse)
            AP_DIR=/etc/apache2
            CONF_SSL_L="$AP_DIR/vhosts.d/$SSL_CONF_NAME.conf"
            CONF_REDIR_L="$AP_DIR/conf.d/$REDIR_CONF_NAME.conf"
            LOG_DIR=/var/log/apache2
            SERVICE=apache2
            for dd_f in "$R"/usr/lib64/apache2*/mod_ssl.so "$R"/usr/lib/apache2*/mod_ssl.so; do
                [ -e "$dd_f" ] && SSL_MODULE=1 && break
            done
            MISSING_HINT='zypper install apache2'
            ;;
        alpine)
            AP_DIR=/etc/apache2
            CONF_SSL_L="$AP_DIR/conf.d/$SSL_CONF_NAME.conf"
            CONF_REDIR_L="$AP_DIR/conf.d/$REDIR_CONF_NAME.conf"
            LOG_DIR=logs
            SERVICE=apache2
            for dd_f in "$R$AP_DIR/conf.d/ssl.conf" "$R"/usr/lib/apache2/mod_ssl.so; do
                [ -e "$dd_f" ] && SSL_MODULE=1 && break
            done
            SSL_ENABLED=$SSL_MODULE
            MISSING_HINT='apk add apache2-ssl'
            ;;
        arch|generic)
            SERVICE=httpd
            [ "$LAYOUT" = generic ] && [ -d "$R/etc/apache2" ] && SERVICE=apache2
            find_generic_confdir
            LOG_DIR=logs
            [ "$LAYOUT" = arch ] && LOG_DIR=/var/log/httpd
            for dd_f in "$R"/usr/lib/httpd/modules/mod_ssl.so "$R"/usr/lib64/httpd/modules/mod_ssl.so \
                        "$R"/usr/lib/apache2/modules/mod_ssl.so "$R"/usr/lib/apache2/mod_ssl.so \
                        "$R"/usr/local/libexec/apache24/mod_ssl.so; do
                if [ -e "$dd_f" ]; then
                    SSL_MODULE=1
                    LOAD_SSL="${dd_f#$R}"
                    break
                fi
            done
            MISSING_HINT='installez le module mod_ssl de votre distribution'
            ;;
    esac

    CONF_DIR=''
    [ -n "$CONF_SSL_L" ] && CONF_DIR=$(dirname "$CONF_SSL_L")

    # nginx : dossier du fragment généré
    NGINX_SNIPPET_L=/etc/nginx/snippets/$SSL_CONF_NAME.conf

    port_probe 443
    PORT443_USED=$PORT_USED
    PORT443_OWNER=$PORT_OWNER

    # Verdict
    SUPPORTED=0; REASON=''; MODE=''
    case "$WEBSERVER" in
        apache)
            if [ -z "$CONF_DIR" ] || [ ! -d "$R$CONF_DIR" ]; then
                REASON="dossier de configuration Apache introuvable pour la famille $LAYOUT"
            elif [ "$LAYOUT" = debian ] && { [ -z "$(srv_cmd a2enmod)" ] || [ -z "$(srv_cmd a2ensite)" ]; }; then
                REASON="a2enmod/a2ensite introuvables"
            elif [ "$SSL_MODULE" != 1 ]; then
                REASON="module TLS d'Apache absent : $MISSING_HINT"
            else
                SUPPORTED=1; MODE=auto
                REASON="Apache $APACHE_VERSION ($LAYOUT) : installation automatique possible"
            fi
            ;;
        nginx)
            SUPPORTED=1; MODE=manual
            REASON="nginx : fragment de configuration généré, inclusion à faire à la main"
            ;;
        *)
            REASON="aucun serveur web pris en charge (Apache ou nginx) détecté"
            ;;
    esac
}

# arch / generic : dossier inclus par la configuration principale d'Apache.
find_generic_confdir() {
    for fg_main in /etc/httpd/conf/httpd.conf /etc/apache2/httpd.conf /etc/apache2/apache2.conf /etc/httpd/httpd.conf /usr/local/etc/apache24/httpd.conf; do
        [ -f "$R$fg_main" ] || continue
        fg_sr=$(sed -n 's/^[[:space:]]*ServerRoot[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$R$fg_main" | head -n 1)
        [ -n "$fg_sr" ] || fg_sr=$(dirname "$fg_main")
        for fg_inc in $(sed -n 's/^[[:space:]]*Include\(Optional\)\{0,1\}[[:space:]]\{1,\}"\{0,1\}\([^"[:space:]]*\)\/\*\.conf.*/\2/p' "$R$fg_main"); do
            case "$fg_inc" in
                /*) ;;
                *) fg_inc="$fg_sr/$fg_inc" ;;
            esac
            if [ -d "$R$fg_inc" ]; then
                AP_DIR=$(dirname "$fg_main")
                CONF_SSL_L="$fg_inc/$SSL_CONF_NAME.conf"
                CONF_REDIR_L="$fg_inc/$REDIR_CONF_NAME.conf"
                return 0
            fi
        done
    done
    return 1
}

print_detect() {
    out os_id "$OS_ID"
    out os_like "$OS_LIKE"
    out os_version "$OS_VERSION"
    out os_name "$OS_NAME"
    out layout "$LAYOUT"
    out webserver "$WEBSERVER"
    out apache_ctl "$APACHE_CTL"
    out apache_version "$APACHE_VERSION"
    out apache_running "$APACHE_RUNNING"
    out nginx_running "$NGINX_RUNNING"
    out docker "$DOCKER"
    out systemd "$SYSTEMD"
    out ssl_module "$SSL_MODULE"
    out ssl_enabled "$SSL_ENABLED"
    out conf_dir "$CONF_DIR"
    out port443_used "$PORT443_USED"
    out port443_owner "$PORT443_OWNER"
    out mode "$MODE"
    out supported "$SUPPORTED"
    out reason "$REASON"
}

# ---------------------------------------------------------------------------
# Apache : outils communs
# ---------------------------------------------------------------------------

# Test de configuration. Sortie dans TEST_OUT, code de retour du test.
apache_test() {
    TEST_OUT=''
    if [ "$DRY" = "1" ]; then
        msg "[simulation] $APACHE_CTL -t"
        return 0
    fi
    if [ -n "$R" ] && is_sys_bin "$APACHE_CTL"; then
        msg "[ACME_ROOT] test de configuration réel non lancé"
        return 0
    fi
    TEST_OUT=$("$APACHE_CTL" -t 2>&1)
}

# Fichier PID du processus maître d'Apache, s'il existe (positionne APACHE_PIDFILE).
apache_pidfile() {
    APACHE_PIDFILE=''
    for ap_f in /run/apache2/apache2.pid /var/run/apache2/apache2.pid /run/httpd/httpd.pid \
                /var/run/httpd/httpd.pid /run/apache2/httpd.pid /var/run/apache2/httpd.pid \
                /run/httpd.pid /var/run/httpd.pid; do
        if [ -f "$R$ap_f" ]; then
            APACHE_PIDFILE="$R$ap_f"
            return 0
        fi
    done
    return 1
}

# apache_alive [port] : attend un peu, puis vérifie qu'Apache tourne toujours
# et, si un port est donné, qu'il l'écoute. Un rechargement « graceful » peut
# réussir (code 0) et Apache s'arrêter juste après, par exemple s'il ne peut
# pas s'attacher à un port (AH00072) : seul ce contrôle le voit.
# Positionne ALIVE_WHY en cas d'échec.
apache_alive() {
    ALIVE_WHY=''
    [ "$DRY" = "1" ] && return 0
    if [ -n "$R" ]; then aa_w="${ACME_RELOAD_WAIT:-0}"; else aa_w="${ACME_RELOAD_WAIT:-3}"; fi
    case "$aa_w" in ''|*[!0-9]*) aa_w=3 ;; esac
    [ "$aa_w" -gt 0 ] && sleep "$aa_w"
    apache_up || return 1
    if [ -n "${1:-}" ]; then
        port_probe "$1"
        if [ "$PORT_USED" = 0 ]; then
            ALIVE_WHY="Apache n'écoute pas sur le port $1"
            return 1
        fi
        case "$PORT_OWNER" in
            ''|unknown|apache2|httpd) ;;
            *) ALIVE_WHY="le port $1 est tenu par « $PORT_OWNER », pas par Apache"; return 1 ;;
        esac
    fi
    return 0
}

# Vrai si le processus maître d'Apache tourne. Le maître garde son PID pendant
# un graceful ; ses fils peuvent lui survivre quelques secondes, d'où le fichier
# PID quand il existe (relevé par apache_pidfile avant le rechargement).
apache_up() {
    if [ -n "${APACHE_PIDFILE:-}" ]; then
        au_pid=$(head -n 1 "$APACHE_PIDFILE" 2>/dev/null | tr -cd '0-9')
        au_comm=''
        [ -n "$au_pid" ] && au_comm=$(cat "$R/proc/$au_pid/comm" 2>/dev/null)
        case "$au_comm" in
            apache2|httpd) return 0 ;;
        esac
        ALIVE_WHY="le processus maître d'Apache s'est arrêté"
        return 1
    fi
    proc_running apache2 httpd && return 0
    ALIVE_WHY="plus aucun processus Apache"
    return 1
}

# Démarrage d'Apache (après un arrêt inattendu). Positionne START_METHOD.
apache_start() {
    START_METHOD=''
    as_sc=$(srv_cmd systemctl) || as_sc=''
    if [ "$SYSTEMD" = 1 ] && [ -n "$as_sc" ]; then
        START_METHOD="systemctl start $SERVICE"
        run_sys "$as_sc" start "$SERVICE" && return 0
    fi
    if [ "$DOCKER" != 1 ]; then
        if as_rc=$(srv_cmd rc-service) && [ -e "$R/etc/init.d/$SERVICE" ]; then
            START_METHOD="rc-service $SERVICE start"
            run_sys "$as_rc" "$SERVICE" start && return 0
        elif as_sv=$(srv_cmd service) && [ -e "$R/etc/init.d/$SERVICE" ]; then
            START_METHOD="service $SERVICE start"
            run_sys "$as_sv" "$SERVICE" start && return 0
        fi
    fi
    case "$APACHE_CTL" in
        */httpd)
            START_METHOD="httpd -k start"
            run_sys "$APACHE_CTL" -k start ;;
        *)
            START_METHOD="$(basename "$APACHE_CTL") start"
            run_sys "$APACHE_CTL" start ;;
    esac
}

# reload_checked [port] : rechargement, puis contrôle qu'Apache a survécu.
# Si Apache est tombé (ou n'écoute pas le port) : restauration complète
# (fichiers + a2dis* de ce qui a été activé), puis redémarrage ou nouveau
# rechargement avec l'ancienne configuration, et sortie en code 11 (9 si la
# restauration ou le redémarrage échoue). Rechargement refusé mais Apache
# toujours là : code 7.
reload_checked() {
    apache_pidfile
    rc_ok=0
    apache_reload || rc_ok=1
    if [ "$RELOAD_METHOD" = skipped ] || apache_alive "${1:-}"; then
        if [ "$rc_ok" != 0 ]; then
            [ -n "$BK_DIR" ] && out backup "$BK_DIR"
            die 7 "configuration valide mais le rechargement d'Apache ($RELOAD_METHOD) a échoué ; Apache tourne toujours"
        fi
        return 0
    fi
    rc_why="$ALIVE_WHY"
    rc_method="$RELOAD_METHOD"
    msg "ERREUR : après « $rc_method », $rc_why. Restauration de l'état précédent…"
    rc_rc=0
    undo_changes || rc_rc=1
    apache_test || { rc_rc=1; msg "$TEST_OUT"; }
    if apache_up; then
        # toujours là (mais pas sur le port) : rechargement de l'ancienne conf
        apache_reload || rc_rc=1
        rc_again="$RELOAD_METHOD"
    else
        apache_pidfile   # un nouveau maître écrira son propre fichier PID
        apache_start || rc_rc=1
        rc_again="$START_METHOD"
    fi
    apache_alive || { rc_rc=1; msg "Apache ne tourne toujours pas après « $rc_again » : $ALIVE_WHY"; }
    [ -n "$BK_DIR" ] && out backup "$BK_DIR"
    out reload "$rc_method"
    out restart "$rc_again"
    if [ "$rc_rc" != 0 ]; then
        die 9 "Apache en échec après « $rc_method » ($rc_why), et la restauration ou le redémarrage (« $rc_again ») a échoué : intervention manuelle nécessaire (sauvegarde : $BK_DIR)"
    fi
    die 11 "Apache en échec après « $rc_method » ($rc_why) : état précédent restauré et Apache relancé (« $rc_again »)"
}

# Rechargement en douceur. Positionne RELOAD_METHOD.
apache_reload() {
    RELOAD_METHOD=''
    if [ "$APACHE_RUNNING" != 1 ]; then
        RELOAD_METHOD=skipped
        msg "Apache ne tourne pas : pas de rechargement, la configuration servira au prochain démarrage."
        return 0
    fi
    ar_sc=$(srv_cmd systemctl) || ar_sc=''
    if [ "$SYSTEMD" = 1 ] && [ -n "$ar_sc" ]; then
        RELOAD_METHOD="systemctl reload $SERVICE"
        run_sys "$ar_sc" reload "$SERVICE" && return 0
        msg "systemctl reload a échoué, essai de graceful."
    fi
    if [ "$DOCKER" != 1 ]; then
        if ar_rc=$(srv_cmd rc-service) && [ -e "$R/etc/init.d/$SERVICE" ]; then
            RELOAD_METHOD="rc-service $SERVICE reload"
            run_sys "$ar_rc" "$SERVICE" reload && return 0
        elif ar_sv=$(srv_cmd service) && [ -e "$R/etc/init.d/$SERVICE" ]; then
            RELOAD_METHOD="service $SERVICE reload"
            run_sys "$ar_sv" "$SERVICE" reload && return 0
        fi
    fi
    case "$APACHE_CTL" in
        */httpd)
            RELOAD_METHOD="httpd -k graceful"
            run_sys "$APACHE_CTL" -k graceful ;;
        *)
            RELOAD_METHOD="$(basename "$APACHE_CTL") graceful"
            run_sys "$APACHE_CTL" graceful ;;
    esac
}

# Fichiers de configuration Apache à parcourir pour y chercher Listen ou le
# vhost du port 80 (hors fichiers gérés par le plugin).
apache_conf_files() {
    case "$LAYOUT" in
        debian)
            for acf in "$R$AP_DIR/apache2.conf" "$R$AP_DIR/ports.conf" \
                       "$R$AP_DIR"/sites-enabled/* "$R$AP_DIR"/conf-enabled/*; do
                [ -f "$acf" ] && printf '%s\n' "$acf"
            done ;;
        *)
            [ -d "$R$AP_DIR" ] && find "$R$AP_DIR" -type f -name '*.conf'
            [ -n "$CONF_DIR" ] && [ "$CONF_DIR" != "$AP_DIR" ] && [ -d "$R$CONF_DIR" ] && \
                find "$R$CONF_DIR" -type f -name '*.conf' ;;
    esac | while IFS= read -r acf; do
        grep -q -F "$MARKER" "$acf" 2>/dev/null || printf '%s\n' "$acf"
    done | sort -u
}

# Vrai si un Listen existant (hors fichiers gérés) couvre déjà le port $1.
listen_exists() {
    apache_conf_files | while IFS= read -r le_f; do
        if grep -q -E "^[[:space:]]*Listen[[:space:]]+([^[:space:]]*:)?$1([[:space:]]|\$)" "$le_f" 2>/dev/null; then
            echo yes
            break
        fi
    done | grep -q yes
}

# Fichiers (hors fichiers gérés) contenant un <VirtualHost …:PORT> sans
# « SSLEngine on » : le port est alors servi en HTTP. Un nom par ligne.
vhost_plain_on_port() {
    apache_conf_files | while IFS= read -r vp_f; do
        awk -v p="$1" '
            {
                l = tolower($0)
                if (!inv) {
                    if (l ~ /^[ \t]*<virtualhost[ \t]/) {
                        n = split(l, w, /[ \t>]+/)
                        for (i = 2; i <= n; i++) {
                            k = split(w[i], a, ":")
                            if (k > 1 && a[k] == p) { inv = 1; ssl = 0 }
                        }
                    }
                    next
                }
                if (l ~ /^[ \t]*sslengine[ \t]+on/) ssl = 1
                if (l ~ /^[ \t]*<\/virtualhost>/) {
                    if (!ssl) { found = 1; exit }
                    inv = 0
                }
            }
            END { exit found ? 0 : 1 }' "$vp_f" 2>/dev/null && printf '%s\n' "${vp_f#$R}"
    done
}

# Extrait du premier <VirtualHost …:80> : ligne « DOCROOT<tab>chemin » puis
# les blocs <Directory> tels quels.
vhost80_extract() {
    apache_conf_files | while IFS= read -r ve_f; do
        cat "$ve_f"
        echo
    done | awk '
        done { next }
        {
            l = tolower($0)
            if (!inv) {
                if (l ~ /^[ \t]*<virtualhost[ \t][^>]*:80[ \t>]/) inv = 1
                next
            }
            if (l ~ /^[ \t]*<\/virtualhost>/) { done = 1; next }
            if (indir == 0 && l ~ /^[ \t]*documentroot[ \t]/) {
                d = $2; gsub(/"/, "", d); print "DOCROOT\t" d; next
            }
            if (l ~ /^[ \t]*<directory[ \t>]/) indir++
            if (indir > 0) print "DIR\t" $0
            if (l ~ /^[ \t]*<\/directory>/) indir--
        }'
}

# ---------------------------------------------------------------------------
# Contrôle des arguments
# ---------------------------------------------------------------------------

# Les grep travaillent ligne par ligne : un retour à la ligne ferait passer
# « nom valide » + « directive Apache ». On refuse donc d'abord tout caractère
# hors de la liste permise (retours à la ligne compris), avant le grep.
valid_domain() {
    vd="$1"
    [ -n "$vd" ] && [ ${#vd} -le 253 ] || return 1
    case "$vd" in
        *[!a-z0-9.*-]*) return 1 ;;
    esac
    printf '%s\n' "$vd" | grep -q -E '^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ] && [ "$1" != 80 ]
}

valid_abspath() {
    case "$1" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *[!A-Za-z0-9._/+-]*|*..*|*//*) return 1 ;;
    esac
    printf '%s\n' "$1" | grep -q -E '^/[A-Za-z0-9._/+-]*$'
}

# Vérifie les deux fichiers PEM, et qu'ils vont ensemble si openssl est là :
# une clé qui ne correspond pas passe « apachectl -t » mais fait tomber
# Apache au rechargement.
check_pem() {
    grep -q -e '-----BEGIN CERTIFICATE-----' "$ARG_FULLCHAIN" || die 2 "$ARG_FULLCHAIN ne contient pas de certificat PEM"
    grep -q -e '-----BEGIN .*PRIVATE KEY-----' "$ARG_KEY" || die 2 "$ARG_KEY ne contient pas de clé privée PEM"
    grep -q -e 'ENCRYPTED' "$ARG_KEY" && die 2 "la clé privée est chiffrée par une phrase de passe : Apache ne pourrait pas la charger sans intervention"
    if cp_ossl=$(tool_cmd openssl); then
        cp_c=$("$cp_ossl" x509 -in "$ARG_FULLCHAIN" -noout -pubkey 2>/dev/null) || die 2 "certificat illisible par openssl : $ARG_FULLCHAIN"
        cp_k=$("$cp_ossl" pkey -in "$ARG_KEY" -pubout 2>/dev/null) || cp_k=''
        if [ -n "$cp_k" ] && [ "$cp_c" != "$cp_k" ]; then
            die 2 "la clé privée ne correspond pas au certificat"
        fi
        if ! "$cp_ossl" x509 -in "$ARG_FULLCHAIN" -noout -checkend 0 >/dev/null 2>&1; then
            msg "ATTENTION : le certificat fourni est déjà expiré."
        fi
    fi
}

# Minuscules. Pas de substitution $(…) seule : elle retirerait les retours à
# la ligne finaux, qu'on veut au contraire voir et refuser.
lower() {
    lw=$(printf '%s.' "$1" | tr '[:upper:]' '[:lower:]')
    printf '%s' "${lw%.}"
}

parse_install_args() {
    ARG_DOMAIN=''; ARG_FULLCHAIN=''; ARG_KEY=''; ARG_PORT=443; ARG_REDIRECT=0; ARG_WEBROOT=''
    ARG_ALIASES=''; ARG_FORCE_PORT=0; ARG_REDIRECT_PORT=''
    while [ $# -gt 0 ]; do
        if [ "$1" = --force-port ]; then
            ARG_FORCE_PORT=1
            shift
            continue
        fi
        [ $# -ge 2 ] || die 2 "valeur manquante pour $1"
        case "$1" in
            --domain)    ARG_DOMAIN=$(lower "$2") ;;
            --alias)
                pa_a=$(lower "$2")
                valid_domain "$pa_a" || die 2 "alias invalide : $pa_a"
                ARG_ALIASES="$ARG_ALIASES $pa_a" ;;
            --fullchain) ARG_FULLCHAIN="$2" ;;
            --key)       ARG_KEY="$2" ;;
            --port)      ARG_PORT="$2" ;;
            --redirect)  ARG_REDIRECT="$2" ;;
            --redirect-port) ARG_REDIRECT_PORT="$2" ;;
            --webroot)   ARG_WEBROOT="$2" ;;
            *) die 2 "option inconnue : $1" ;;
        esac
        shift 2
    done
    [ -n "$ARG_DOMAIN" ] || die 2 "--domain est obligatoire"
    valid_domain "$ARG_DOMAIN" || die 2 "nom de domaine invalide : $ARG_DOMAIN"
    [ -n "$ARG_FULLCHAIN" ] && [ -f "$ARG_FULLCHAIN" ] && [ -r "$ARG_FULLCHAIN" ] || die 2 "fichier fullchain introuvable ou illisible : $ARG_FULLCHAIN"
    [ -n "$ARG_KEY" ] && [ -f "$ARG_KEY" ] && [ -r "$ARG_KEY" ] || die 2 "fichier de clé introuvable ou illisible : $ARG_KEY"
    valid_port "$ARG_PORT" || die 2 "port invalide : $ARG_PORT (1 à 65535, sauf 80)"
    [ -n "$ARG_REDIRECT_PORT" ] || ARG_REDIRECT_PORT="$ARG_PORT"
    valid_port "$ARG_REDIRECT_PORT" || die 2 "port de redirection invalide : $ARG_REDIRECT_PORT (1 à 65535, sauf 80)"
    case "$ARG_REDIRECT" in
        0|1) ;;
        true|yes|on) ARG_REDIRECT=1 ;;
        false|no|off|'') ARG_REDIRECT=0 ;;
        *) die 2 "--redirect attend 0 ou 1" ;;
    esac
    if [ -n "$ARG_WEBROOT" ]; then
        ARG_WEBROOT="${ARG_WEBROOT%/}"
        valid_abspath "$ARG_WEBROOT" || die 2 "chemin webroot invalide : $ARG_WEBROOT"
        [ -d "$R$ARG_WEBROOT" ] || die 2 "dossier webroot introuvable : $R$ARG_WEBROOT"
    fi
    DOMAIN_DIR="${ARG_DOMAIN#\*.}"
    case "$DOMAIN_DIR" in
        ''|*/*|*..*|.*) die 2 "nom de domaine invalide : $ARG_DOMAIN" ;;
    esac
    # NAMES : noms couverts, sans doublon, le principal d'abord. Les boucles
    # sur ces listes coupent le développement des jokers (set -f) : « *.x »
    # ne doit pas être remplacé par des noms de fichiers.
    set -f
    NAMES="$ARG_DOMAIN"
    for pa_a in $ARG_ALIASES; do
        case " $NAMES " in
            *" $pa_a "*) ;;
            *) NAMES="$NAMES $pa_a" ;;
        esac
    done
    ALIASES=''
    for pa_a in $NAMES; do
        [ "$pa_a" = "$DOMAIN_DIR" ] || ALIASES="$ALIASES${ALIASES:+ }$pa_a"
    done
    set +f
    check_pem
}

# ---------------------------------------------------------------------------
# Génération des fichiers
# ---------------------------------------------------------------------------

gen_ssl_conf() {
    printf '# %s — %s.\n' "$SSL_CONF_NAME" "$MARKER"
    printf '# Ne pas modifier : ce fichier est réécrit à chaque installation du certificat\n'
    printf '# et supprimé par « Désinstaller du serveur web ». Généré le %s.\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '# Domaine : %s — port : %s\n' "$ARG_DOMAIN" "$ARG_PORT"
    [ -n "$ALIASES" ] && printf '# Alias : %s\n' "$ALIASES"
    if [ -n "$LOAD_SSL" ]; then
        printf '<IfModule !mod_ssl.c>\n    LoadModule ssl_module %s\n</IfModule>\n' "$LOAD_SSL"
    fi
    printf '<IfModule mod_ssl.c>\n'
    if [ "$NEED_LISTEN" = 1 ]; then
        printf '    Listen %s https\n' "$ARG_PORT"
    fi
    printf '    <VirtualHost *:%s>\n' "$ARG_PORT"
    printf '        ServerName %s\n' "$DOMAIN_DIR"
    set -f
    for gs_a in $ALIASES; do
        printf '        ServerAlias %s\n' "$gs_a"
    done
    set +f
    printf '        DocumentRoot %s\n' "$WEBROOT"
    printf '%s\n' "$DIR_BLOCKS"
    # Le cœur de Jeedom ne pose un cookie de session « Secure » que s'il se
    # sait en HTTPS : on le lui dit (valeur écrasée, jamais celle du client).
    printf '        <IfModule mod_headers.c>\n'
    printf '            RequestHeader set X-Forwarded-Proto "https"\n'
    printf '        </IfModule>\n'
    printf '        SSLEngine on\n'
    printf '        SSLCertificateFile %s\n' "$FULLCHAIN_L"
    printf '        SSLCertificateKeyFile %s\n' "$KEY_L"
    printf '        SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n'
    printf '        SSLHonorCipherOrder off\n'
    printf '        ErrorLog %s/jeedom-acme-ssl_error.log\n' "$LOG_DIR"
    printf '        CustomLog %s/jeedom-acme-ssl_access.log combined\n' "$LOG_DIR"
    printf '    </VirtualHost>\n'
    printf '</IfModule>\n'
}

# Redirection HTTP → HTTPS. Voir le commentaire généré pour le pourquoi.
# Expression régulière des noms couverts : un nom exact, ou un seul niveau de
# sous-domaine pour un joker (comme le certificat lui-même).
names_regex() {
    nr_re=''
    set -f
    for nr_n in $NAMES; do
        nr_e=$(printf '%s' "${nr_n#\*.}" | sed 's/\./\\./g')
        case "$nr_n" in
            \*.*) nr_e="[^.]+\\.$nr_e" ;;
        esac
        nr_re="$nr_re${nr_re:+|}$nr_e"
    done
    set +f
    printf '%s' "$nr_re"
}

gen_redirect_conf() {
    gr_host=$(names_regex)
    gr_port=''
    # Port vu depuis Internet (routeur : port public → Jeedom:$ARG_PORT).
    [ "$ARG_REDIRECT_PORT" = 443 ] || gr_port=":$ARG_REDIRECT_PORT"
    # Pas de redirection si un proxy en amont dit que le client est déjà en
    # HTTPS (X-Forwarded-Proto, X-Forwarded-Ssl, Forwarded: proto=https).
    gr_cond="%{HTTPS} != 'on' && req('X-Forwarded-Proto') !~ m#^https#i && req('X-Forwarded-Ssl') !~ m#^on\$#i && req('Forwarded') !~ m#proto=.?https#i && %{HTTP_HOST} =~ m#^($gr_host)(:[0-9]+)?\$#i && %{REQUEST_URI} !~ m#^/\\.well-known/acme-challenge/#"
    printf '# %s — %s.\n' "$REDIR_CONF_NAME" "$MARKER"
    printf '# Ne pas modifier : réécrit à chaque installation, supprimé à la désinstallation.\n'
    printf '# Redirige vers HTTPS les requêtes HTTP adressées aux noms du certificat\n'
    printf '# (%s), et à eux seuls :\n' "$NAMES"
    printf '# les accès par adresse IP ou par localhost (appels internes de Jeedom et de\n'
    printf '# ses démons) restent en HTTP. /.well-known/acme-challenge/ n'"'"'est jamais\n'
    printf '# redirigé (renouvellement HTTP-01). Placé au niveau du serveur, ce bloc\n'
    printf '# <If> s'"'"'applique à tous les VirtualHost sans modifier leurs fichiers.\n'
    printf '# Redirection temporaire (302) : les navigateurs ne la mémorisent pas, ce qui\n'
    printf '# permet de revenir en arrière sans piège.\n'
    printf '<IfModule mod_alias.c>\n'
    printf '    <If "%s && -z %%{QUERY_STRING}">\n' "$gr_cond"
    printf '        Redirect temp "https://%%{SERVER_NAME}%s%%{REQUEST_URI}"\n' "$gr_port"
    printf '    </If>\n'
    printf '    <If "%s && -n %%{QUERY_STRING}">\n' "$gr_cond"
    printf '        Redirect temp "https://%%{SERVER_NAME}%s%%{REQUEST_URI}?%%{QUERY_STRING}"\n' "$gr_port"
    printf '    </If>\n'
    printf '</IfModule>\n'
}

# Blocs <Directory> du vhost 80 (Jeedom a besoin de son .htaccess), ou bloc
# par défaut AllowOverride All. Positionne WEBROOT et DIR_BLOCKS.
prepare_directory_blocks() {
    pd_ext=$(vhost80_extract)
    pd_tab=$(printf '\t')
    pd_doc=$(printf '%s\n' "$pd_ext" | sed -n "s/^DOCROOT$pd_tab//p" | head -n 1)
    WEBROOT="$ARG_WEBROOT"
    if [ -z "$WEBROOT" ]; then
        WEBROOT="${pd_doc%/}"
        if [ -z "$WEBROOT" ] || ! valid_abspath "$WEBROOT"; then
            WEBROOT=/var/www/html
        fi
    fi
    DIR_BLOCKS=$(printf '%s\n' "$pd_ext" | sed -n "s/^DIR$pd_tab/    /p")
    # Le bloc du vhost 80 couvre-t-il le webroot ?
    pd_cover=0
    for pd_d in $(printf '%s\n' "$DIR_BLOCKS" | sed -n 's/^[[:space:]]*<[Dd][Ii][Rr][Ee][Cc][Tt][Oo][Rr][Yy][[:space:]]\{1,\}"\{0,1\}\([^">]*\)"\{0,1\}>.*/\1/p'); do
        [ "${pd_d%/}" = "$WEBROOT" ] && pd_cover=1
    done
    if [ -n "$DIR_BLOCKS" ]; then
        msg "Blocs <Directory> repris du VirtualHost du port 80."
    fi
    if [ "$pd_cover" = 0 ]; then
        pd_def=$(printf '        <Directory %s>\n            AllowOverride All\n            Require all granted\n        </Directory>' "$WEBROOT")
        if [ -n "$DIR_BLOCKS" ]; then
            DIR_BLOCKS="$DIR_BLOCKS
$pd_def"
        else
            DIR_BLOCKS="$pd_def"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

need_root() {
    [ "$(id -u)" = "0" ] && return 0
    [ "$DRY" = "1" ] && return 0
    [ -n "$R" ] && return 0
    die 3 "ce script doit être lancé en root (sudo), ou avec ACME_DRYRUN=1 / ACME_ROOT pour un essai"
}

# Fichier géré ? (présent et marqué)
is_managed() {
    [ -f "$1" ] && grep -q -F "$MARKER" "$1" 2>/dev/null
}

# Liste des noms présents dans un dossier *-enabled (Debian).
enabled_list() {
    ls -1 "$R$AP_DIR/$1" 2>/dev/null
}

# Défait tout : désactive (Debian) ce qui a été activé depuis snapshot_enabled,
# puis restaure les fichiers du manifeste. Renvoie 1 si un élément résiste.
undo_changes() {
    uc_rc=0
    if [ "$LAYOUT" = debian ] && [ "$SNAPSHOT_DONE" = 1 ]; then
        for uc_m in $(enabled_list mods-enabled | sed -n 's/\.load$//p'); do
            printf '%s\n' "$MODS_BEFORE" | grep -q -x -F "$uc_m.load" && continue
            run_tool a2dismod -q -f "$uc_m" || uc_rc=1
        done
        for uc_s in $(enabled_list sites-enabled | sed -n 's/\.conf$//p'); do
            printf '%s\n' "$SITES_BEFORE" | grep -q -x -F "$uc_s.conf" && continue
            run_tool a2dissite -q "$uc_s" || uc_rc=1
        done
        for uc_c in $(enabled_list conf-enabled | sed -n 's/\.conf$//p'); do
            printf '%s\n' "$CONFS_BEFORE" | grep -q -x -F "$uc_c.conf" && continue
            run_tool a2disconf -q "$uc_c" || uc_rc=1
        done
    fi
    bk_restore || uc_rc=1
    return $uc_rc
}

# rollback_and_die [code message]
# Sans argument : échec du test de configuration (sortie dans TEST_OUT), code 6.
# Avec : échec d'une étape (copie, sauvegarde…), sortie avec ce code.
# Dans les deux cas tout est restauré ; restauration incomplète → code 9.
rollback_and_die() {
    rb_code="${1:-6}"
    rb_why="${2:-}"
    if [ -z "$rb_why" ]; then
        msg "Le test de configuration a échoué :"
        msg "$TEST_OUT"
    else
        msg "Échec : $rb_why"
    fi
    msg "Restauration de l'état précédent…"
    rb_rc=0
    undo_changes || rb_rc=1
    rb_first="$TEST_OUT"
    if [ "$WEBSERVER" = apache ] && [ -n "${APACHE_CTL:-}" ] && ! apache_test; then
        rb_rc=1
    fi
    [ -n "$BK_DIR" ] && out backup "$BK_DIR"
    [ -z "$rb_why" ] && out test_output "$rb_first"
    if [ "$rb_rc" != 0 ]; then
        if [ -n "$rb_why" ]; then
            die 9 "$rb_why ET restauration incomplète : vérifiez à la main (sauvegarde : $BK_DIR)"
        fi
        die 9 "échec du test de configuration ET restauration incomplète : vérifiez à la main (sauvegarde : $BK_DIR). Sortie du test : $rb_first"
    fi
    if [ -n "$rb_why" ]; then
        die "$rb_code" "$rb_why : rien n'a été changé, état précédent restauré"
    fi
    die 6 "configuration refusée par Apache, état précédent restauré. Sortie du test : $rb_first"
}

# Snapshot des modules/sites/confs activés (Debian).
snapshot_enabled() {
    MODS_BEFORE=''; SITES_BEFORE=''; CONFS_BEFORE=''
    if [ "$LAYOUT" = debian ]; then
        MODS_BEFORE=$(enabled_list mods-enabled)
        SITES_BEFORE=$(enabled_list sites-enabled)
        CONFS_BEFORE=$(enabled_list conf-enabled)
    fi
    SNAPSHOT_DONE=1
}

# Test préalable : si la configuration est déjà cassée, on ne touche à rien,
# sinon on ne saurait pas distinguer notre erreur d'une erreur existante.
pretest_or_die() {
    if ! apache_test; then
        out test_output "$TEST_OUT"
        die 8 "la configuration d'Apache est déjà invalide avant toute modification, rien n'a été fait : $TEST_OUT"
    fi
}

# Retire les dossiers de certificats d'un ancien domaine.
prune_old_cert_dirs() {
    for po_d in "$CERT_ROOT"/*; do
        [ -d "$po_d" ] || continue
        [ "$(basename "$po_d")" = "$DOMAIN_DIR" ] && continue
        bk_path "$po_d"
        [ "$DRY" = "1" ] || rm -rf "$po_d"
    done
}

# stage_file source destination mode : copie la source dans un fichier
# temporaire voisin de la destination (même dossier, donc même système de
# fichiers : le mv final est atomique). Affiche le chemin du temporaire.
stage_file() {
    sf_tmp="$2.acme-new.$$"
    ( umask 077; cat "$1" > "$sf_tmp" ) || { rm -f "$sf_tmp"; return 1; }
    [ -s "$sf_tmp" ] || { rm -f "$sf_tmp"; return 1; }
    chmod "$3" "$sf_tmp" || { rm -f "$sf_tmp"; return 1; }
    if [ "$(id -u)" = "0" ]; then
        chown 0:0 "$sf_tmp" 2>/dev/null
    fi
    printf '%s\n' "$sf_tmp"
}

# Le certificat et la clé vont par paire : une paire désassortie passe
# « apachectl -t » mais fait tomber Apache au rechargement. Les deux fichiers
# sont donc préparés côte à côte, puis mis en place par deux mv ; au moindre
# échec, tout est restauré avant de sortir.
install_certs() {
    FULLCHAIN_L="$CERT_ROOT_L/$DOMAIN_DIR/fullchain.pem"
    KEY_L="$CERT_ROOT_L/$DOMAIN_DIR/privkey.pem"
    bk_path "$CERT_ROOT"
    if [ "$DRY" = "1" ]; then
        msg "[simulation] création de $CERT_ROOT/$DOMAIN_DIR (0700)"
        msg "[simulation] copie de $ARG_FULLCHAIN vers $R$FULLCHAIN_L (0644) et de $ARG_KEY vers $R$KEY_L (0600)"
        return 0
    fi
    ( umask 077; mkdir -p "$CERT_ROOT/$DOMAIN_DIR" ) || rollback_and_die 1 "impossible de créer $CERT_ROOT/$DOMAIN_DIR"
    chmod 700 "$CERT_ROOT" "$CERT_ROOT/$DOMAIN_DIR"
    [ "$(id -u)" = "0" ] && chown 0:0 "$CERT_ROOT" "$CERT_ROOT/$DOMAIN_DIR"
    ic_fc=$(stage_file "$ARG_FULLCHAIN" "$R$FULLCHAIN_L" 0644) || rollback_and_die 1 "copie du certificat impossible"
    if ! ic_k=$(stage_file "$ARG_KEY" "$R$KEY_L" 0600); then
        rm -f "$ic_fc"
        rollback_and_die 1 "copie de la clé impossible"
    fi
    if ! mv -f "$ic_fc" "$R$FULLCHAIN_L"; then
        rm -f "$ic_fc" "$ic_k"
        rollback_and_die 1 "mise en place du certificat impossible"
    fi
    if ! mv -f "$ic_k" "$R$KEY_L"; then
        rm -f "$ic_k"
        rollback_and_die 1 "mise en place de la clé impossible (certificat et clé restaurés ensemble)"
    fi
    prune_old_cert_dirs
}

# Chemin web du dossier data/ du plugin (/plugins/<id>/data/), déduit de
# l'emplacement du script : <webroot>/plugins/<id>/resources/acme_webserver.sh.
# L'identifiant vient de plugin_info/info.json (le dossier d'un dépôt de
# développement peut porter un autre nom) ; « acme » à défaut.
plugin_data_url() {
    pu_info="$(dirname "$(dirname "$SCRIPT_PATH")")/plugin_info/info.json"
    pu_id=$(sed -n 's/^[[:space:]]*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pu_info" 2>/dev/null | head -n 1)
    case "$pu_id" in
        ''|*[!A-Za-z0-9_-]*) pu_id=acme ;;
    esac
    printf '/plugins/%s/data/' "$pu_id"
}

action_install_nginx() {
    install_certs
    NG_DATA=$(plugin_data_url)
    NG_NAMES=$(printf '%s' "$NAMES")
    NG_SNIP="$R$NGINX_SNIPPET_L"
    if [ -f "$NG_SNIP" ] && ! is_managed "$NG_SNIP"; then
        die 1 "$NG_SNIP existe et n'a pas été créé par le plugin : rien n'a été écrit"
    fi
    {
        printf '# %s — %s.\n' "$SSL_CONF_NAME" "$MARKER"
        printf '# Réécrit à chaque installation. À inclure dans un bloc server { listen %s ssl; … }.\n' "$ARG_PORT"
        printf 'ssl_certificate %s;\n' "$FULLCHAIN_L"
        printf 'ssl_certificate_key %s;\n' "$KEY_L"
        printf 'ssl_protocols TLSv1.2 TLSv1.3;\n'
        printf 'ssl_prefer_server_ciphers off;\n'
        printf 'ssl_session_cache shared:jeedom_acme:1m;\n'
        printf 'ssl_session_timeout 1d;\n'
        printf '# data/ du plugin (clés privées) : protégé sous Apache par un .htaccess,\n'
        printf '# que nginx ignore. À ne jamais servir.\n'
        printf 'location ^~ %s { deny all; }\n' "$NG_DATA"
    } | write_file "$NG_SNIP" 0644 || die 1 "écriture de $NG_SNIP impossible"

    # Le fragment est-il déjà inclus par la configuration de l'utilisateur ?
    NG_INCLUDED=0
    if [ -d "$R/etc/nginx" ] && find "$R/etc/nginx" -type f ! -name "$SSL_CONF_NAME.conf" \
            -exec grep -l -F "$SSL_CONF_NAME.conf" {} + 2>/dev/null | grep -q .; then
        NG_INCLUDED=1
    fi
    RELOAD_METHOD=none
    if [ "$NG_INCLUDED" = 1 ] && [ -n "$NGINX_BIN" ]; then
        if [ "$DRY" = "1" ] || { [ -n "$R" ] && is_sys_bin "$NGINX_BIN"; }; then
            ng_out=''
        elif ! ng_out=$("$NGINX_BIN" -t 2>&1); then
            out test_output "$ng_out"
            die 6 "nginx -t échoue : vérifiez votre configuration ($ng_out)"
        fi
        if [ "$NGINX_RUNNING" = 1 ]; then
            if [ "$SYSTEMD" = 1 ] && ng_sc=$(srv_cmd systemctl); then
                RELOAD_METHOD="systemctl reload nginx"
                run_sys "$ng_sc" reload nginx || die 7 "rechargement de nginx en échec"
            else
                RELOAD_METHOD="nginx -s reload"
                run_sys "$NGINX_BIN" -s reload || die 7 "rechargement de nginx en échec"
            fi
        fi
    fi
    [ "$DRY" = "1" ] || bk_prune

    msg ""
    msg "nginx : installation semi-automatique."
    msg "Certificat copié dans $CERT_ROOT_L/$DOMAIN_DIR/ et fragment écrit dans $NGINX_SNIPPET_L."
    if [ "$NG_INCLUDED" = 1 ]; then
        msg "Le fragment est déjà inclus par votre configuration : nginx a été rechargé."
    else
        msg "Ajoutez un bloc server de ce type (aucun bloc existant n'a été modifié), puis"
        msg "« nginx -t && systemctl reload nginx » :"
        msg ""
        msg "server {"
        msg "    listen $ARG_PORT ssl;"
        msg "    listen [::]:$ARG_PORT ssl;"
        msg "    server_name $NG_NAMES;"
        msg "    include $NGINX_SNIPPET_L;"
        msg "    root ${ARG_WEBROOT:-/var/www/html};"
        msg "    # indispensable (déjà dans le fragment, à mettre aussi dans le server du"
        msg "    # port 80) : nginx ignore le .htaccess qui protège les clés du plugin"
        msg "    location ^~ $NG_DATA { deny all; }"
        msg "    # … reprendre ici les directives location du server du port 80 (PHP, etc.)"
        msg "}"
    fi
    out result ok
    out mode manual
    out webserver nginx
    out layout "$LAYOUT"
    out domain "$ARG_DOMAIN"
    out port "$ARG_PORT"
    out cert_dir "$CERT_ROOT_L/$DOMAIN_DIR"
    out fullchain "$FULLCHAIN_L"
    out key "$KEY_L"
    out snippet "$NGINX_SNIPPET_L"
    out included "$NG_INCLUDED"
    out reload "$RELOAD_METHOD"
    out include_line "include $NGINX_SNIPPET_L;"
    out aliases "$ALIASES"
    out data_deny "location ^~ $NG_DATA { deny all; }"
    out instructions "Ajouter dans un bloc server { listen $ARG_PORT ssl; server_name $NG_NAMES; include $NGINX_SNIPPET_L; ... } puis nginx -t et recharger nginx. Ajouter aussi location ^~ $NG_DATA { deny all; } dans le server du port 80 : nginx ignore le .htaccess qui protège les clés privées du plugin"
    [ -n "$BK_DIR" ] && out backup "$BK_DIR"
    out dryrun "$DRY"
    exit 0
}

action_install() {
    need_root
    parse_install_args "$@"
    do_detect
    case "$WEBSERVER" in
        nginx) action_install_nginx ;;
        apache) ;;
        *) die 4 "$REASON" ;;
    esac
    if [ "$SUPPORTED" != 1 ]; then
        if [ "$SSL_MODULE" != 1 ] && [ -n "$CONF_DIR" ]; then
            die 5 "$REASON"
        fi
        die 4 "$REASON"
    fi
    if [ "$ARG_REDIRECT" = 1 ] && [ -n "$APACHE_VERSION" ]; then
        # Redirect avec expression dans <If> : Apache 2.4.19 au minimum.
        ai_minor=$(printf '%s' "$APACHE_VERSION" | cut -d. -f2)
        ai_patch=$(printf '%s' "$APACHE_VERSION" | cut -d. -f3)
        if [ "${ai_minor:-0}" -lt 4 ] || { [ "${ai_minor:-0}" -eq 4 ] && [ "${ai_patch:-0}" -lt 19 ]; }; then
            die 4 "la redirection HTTPS demande Apache 2.4.19 ou plus récent (version $APACHE_VERSION)"
        fi
    fi

    CONF_SSL="$R$CONF_SSL_L"
    CONF_REDIR="$R$CONF_REDIR_L"
    for ai_f in "$CONF_SSL" "$CONF_REDIR"; do
        if [ -f "$ai_f" ] && ! is_managed "$ai_f"; then
            die 1 "$ai_f existe et n'a pas été créé par le plugin : rien n'a été modifié"
        fi
    done

    # Port : Listen déjà présent ? occupé par un autre programme ?
    NEED_LISTEN=1
    listen_exists "$ARG_PORT" && NEED_LISTEN=0
    port_probe "$ARG_PORT"
    if [ "$PORT_USED" = 1 ]; then
        case "$PORT_OWNER" in
            apache2|httpd) ;;
            *)
                if [ "$NEED_LISTEN" = 1 ] || [ "$PORT_OWNER" != unknown ]; then
                    die 10 "le port $ARG_PORT est déjà utilisé par « $PORT_OWNER » : Apache ne pourrait pas s'y attacher et s'arrêterait au rechargement"
                fi ;;
        esac
    elif [ "$PORT_USED" = unknown ] && [ "$NEED_LISTEN" = 1 ]; then
        if [ "$ARG_FORCE_PORT" = 1 ]; then
            msg "ATTENTION : impossible de vérifier que le port $ARG_PORT est libre (ni ss ni netstat) ; installation forcée (--force-port)."
        else
            die 12 "impossible de vérifier que le port $ARG_PORT est libre (ni ss ni netstat disponibles) : s'il est pris, Apache s'arrêterait au rechargement. Installez iproute2 (ss), choisissez un port déjà déclaré par un Listen d'Apache, ou forcez (--force-port)"
        fi
    fi
    # Port déjà servi en HTTP par un VirtualHost non géré (ex. 8080) : notre
    # vhost TLS s'y mélangerait (même port, HTTP et HTTPS).
    ai_http=$(vhost_plain_on_port "$ARG_PORT")
    if [ -n "$ai_http" ]; then
        die 10 "le port $ARG_PORT est déjà servi en HTTP par Apache ($ai_http, VirtualHost sans SSLEngine on) : choisissez un autre port HTTPS"
    fi

    prepare_directory_blocks
    [ -d "$R$WEBROOT" ] || die 2 "dossier webroot introuvable : $R$WEBROOT"

    pretest_or_die
    snapshot_enabled
    msg "Installation du certificat $ARG_DOMAIN dans Apache ($LAYOUT, port $ARG_PORT)…"

    install_certs

    # Modules (Debian ; ailleurs mod_ssl est chargé par sa propre conf, ou par
    # le LoadModule conditionnel de notre fichier pour arch/generic).
    # mod_headers : pour « RequestHeader set X-Forwarded-Proto https » (cookie
    # de session Secure). Activé s'il est disponible ; sinon le bloc
    # <IfModule mod_headers.c> du vhost ne fait simplement rien. Le retour
    # arrière le désactive s'il ne l'était pas avant.
    if [ "$LAYOUT" = debian ]; then
        ai_mods='ssl'
        [ -f "$R$AP_DIR/mods-available/headers.load" ] && ai_mods="$ai_mods headers"
        [ "$ARG_REDIRECT" = 1 ] && ai_mods="$ai_mods alias"
        for ai_m in $ai_mods; do
            if [ ! -e "$R$AP_DIR/mods-enabled/$ai_m.load" ]; then
                msg "Activation du module $ai_m"
                run_tool a2enmod -q "$ai_m" || { TEST_OUT="a2enmod $ai_m a échoué"; rollback_and_die; }
            fi
        done
    elif [ "$LAYOUT" = suse ]; then
        # a2enmod et a2enflag modifient ce fichier : sauvegardé d'abord.
        bk_path "$R/etc/sysconfig/apache2"
        if ai_a2=$(srv_cmd a2enmod); then
            run_sys "$ai_a2" ssl || true
            run_sys "$ai_a2" headers || true
        fi
        if ai_fl=$(srv_cmd a2enflag); then
            run_sys "$ai_fl" SSL || true
        fi
    fi

    # Fichier du vhost TLS
    bk_path "$CONF_SSL"
    gen_ssl_conf | write_file "$CONF_SSL" 0644 || { TEST_OUT="écriture de $CONF_SSL impossible"; rollback_and_die; }
    if [ "$LAYOUT" = debian ]; then
        bk_path "$R$AP_DIR/sites-enabled/$SSL_CONF_NAME.conf"
        if [ ! -e "$R$AP_DIR/sites-enabled/$SSL_CONF_NAME.conf" ]; then
            run_tool a2ensite -q "$SSL_CONF_NAME" || { TEST_OUT="a2ensite a échoué"; rollback_and_die; }
        fi
    fi

    # Redirection
    bk_path "$CONF_REDIR"
    [ "$LAYOUT" = debian ] && bk_path "$R$AP_DIR/conf-enabled/$REDIR_CONF_NAME.conf"
    if [ "$ARG_REDIRECT" = 1 ]; then
        gen_redirect_conf | write_file "$CONF_REDIR" 0644 || { TEST_OUT="écriture de $CONF_REDIR impossible"; rollback_and_die; }
        if [ "$LAYOUT" = debian ] && [ ! -e "$R$AP_DIR/conf-enabled/$REDIR_CONF_NAME.conf" ]; then
            run_tool a2enconf -q "$REDIR_CONF_NAME" || { TEST_OUT="a2enconf a échoué"; rollback_and_die; }
        fi
    elif [ -f "$CONF_REDIR" ]; then
        msg "Retrait de la redirection HTTPS installée précédemment"
        if [ "$LAYOUT" = debian ] && [ -e "$R$AP_DIR/conf-enabled/$REDIR_CONF_NAME.conf" ]; then
            run_tool a2disconf -q "$REDIR_CONF_NAME"
        fi
        [ "$DRY" = "1" ] || rm -f "$CONF_REDIR"
    fi

    if ! apache_test; then
        rollback_and_die
    fi
    msg "Configuration valide."
    reload_checked "$ARG_PORT"
    [ "$DRY" = "1" ] || bk_prune
    msg "Certificat installé : https://$DOMAIN_DIR$( [ "$ARG_PORT" = 443 ] || printf ':%s' "$ARG_PORT")/"

    out result ok
    out mode auto
    out webserver apache
    out layout "$LAYOUT"
    out domain "$ARG_DOMAIN"
    out aliases "$ALIASES"
    out port "$ARG_PORT"
    out redirect "$ARG_REDIRECT"
    out redirect_port "$ARG_REDIRECT_PORT"
    out webroot "$WEBROOT"
    out cert_dir "$CERT_ROOT_L/$DOMAIN_DIR"
    out fullchain "$FULLCHAIN_L"
    out key "$KEY_L"
    out conf_ssl "$CONF_SSL_L"
    [ "$ARG_REDIRECT" = 1 ] && out conf_redirect "$CONF_REDIR_L"
    out listen_added "$NEED_LISTEN"
    out reload "$RELOAD_METHOD"
    [ -n "$BK_DIR" ] && out backup "$BK_DIR"
    out dryrun "$DRY"
    exit 0
}

action_reload() {
    need_root
    do_detect
    case "$WEBSERVER" in
        apache)
            if ! apache_test; then
                out test_output "$TEST_OUT"
                die 6 "configuration invalide, rechargement annulé : $TEST_OUT"
            fi
            apache_pidfile
            rl_rc=0
            apache_reload || rl_rc=1
            if [ "$RELOAD_METHOD" != skipped ] && ! apache_alive; then
                rl_why="$ALIVE_WHY"
                apache_pidfile
                if apache_start && apache_alive; then
                    die 7 "Apache s'est arrêté après « $RELOAD_METHOD » ($rl_why) ; relancé par « $START_METHOD »"
                fi
                die 7 "Apache s'est arrêté après « $RELOAD_METHOD » ($rl_why) et « $START_METHOD » n'a pas suffi à le relancer"
            fi
            [ "$rl_rc" = 0 ] || die 7 "rechargement d'Apache ($RELOAD_METHOD) en échec"
            ;;
        nginx)
            if [ "$DRY" != "1" ] && [ -n "$NGINX_BIN" ] && ! { [ -n "$R" ] && is_sys_bin "$NGINX_BIN"; }; then
                rl_out=$("$NGINX_BIN" -t 2>&1) || { out test_output "$rl_out"; die 6 "nginx -t échoue, rechargement annulé : $rl_out"; }
            fi
            RELOAD_METHOD=skipped
            if [ "$NGINX_RUNNING" = 1 ]; then
                if [ "$SYSTEMD" = 1 ] && rl_sc=$(srv_cmd systemctl); then
                    RELOAD_METHOD="systemctl reload nginx"
                    run_sys "$rl_sc" reload nginx || die 7 "rechargement de nginx en échec"
                else
                    RELOAD_METHOD="nginx -s reload"
                    run_sys "$NGINX_BIN" -s reload || die 7 "rechargement de nginx en échec"
                fi
            fi
            ;;
        *) die 4 "$REASON" ;;
    esac
    out result ok
    out webserver "$WEBSERVER"
    out reload "$RELOAD_METHOD"
    out dryrun "$DRY"
    exit 0
}

action_uninstall() {
    need_root
    do_detect
    if [ "$WEBSERVER" = nginx ]; then
        NG_SNIP="$R$NGINX_SNIPPET_L"
        if [ -d "$R/etc/nginx" ] && find "$R/etc/nginx" -type f ! -name "$SSL_CONF_NAME.conf" \
                -exec grep -l -F "$SSL_CONF_NAME.conf" {} + 2>/dev/null | grep -q .; then
            die 1 "le fragment $NGINX_SNIPPET_L est encore inclus par votre configuration nginx : retirez d'abord cet include"
        fi
        un_did=0
        if is_managed "$NG_SNIP"; then
            [ "$DRY" = "1" ] || rm -f "$NG_SNIP"
            un_did=1
        fi
        if [ -d "$CERT_ROOT" ]; then
            [ "$DRY" = "1" ] || rm -rf "$CERT_ROOT"
            un_did=1
        fi
        out result ok
        out webserver nginx
        out removed "$un_did"
        out dryrun "$DRY"
        exit 0
    fi
    [ "$WEBSERVER" = apache ] || die 4 "$REASON"
    [ -n "$CONF_SSL_L" ] || die 4 "$REASON"
    CONF_SSL="$R$CONF_SSL_L"
    CONF_REDIR="$R$CONF_REDIR_L"
    un_any=0
    is_managed "$CONF_SSL" && un_any=1
    is_managed "$CONF_REDIR" && un_any=1
    if [ "$un_any" = 0 ] && [ ! -d "$CERT_ROOT" ]; then
        msg "Rien à désinstaller : aucune configuration du plugin trouvée."
        out result ok
        out removed 0
        out dryrun "$DRY"
        exit 0
    fi
    pretest_or_die
    snapshot_enabled
    if [ "$LAYOUT" = debian ]; then
        for un_pair in "sites-enabled:$SSL_CONF_NAME:a2dissite" "conf-enabled:$REDIR_CONF_NAME:a2disconf"; do
            un_dir=$(printf '%s' "$un_pair" | cut -d: -f1)
            un_name=$(printf '%s' "$un_pair" | cut -d: -f2)
            un_cmd=$(printf '%s' "$un_pair" | cut -d: -f3)
            bk_path "$R$AP_DIR/$un_dir/$un_name.conf"
            if [ -e "$R$AP_DIR/$un_dir/$un_name.conf" ] || [ -L "$R$AP_DIR/$un_dir/$un_name.conf" ]; then
                run_tool "$un_cmd" -q "$un_name" || { TEST_OUT="$un_cmd a échoué"; rollback_and_die; }
            fi
        done
    fi
    for un_f in "$CONF_SSL" "$CONF_REDIR"; do
        if is_managed "$un_f"; then
            bk_path "$un_f"
            if [ "$DRY" = "1" ]; then msg "[simulation] suppression de $un_f"; else rm -f "$un_f"; fi
        fi
    done
    if [ -d "$CERT_ROOT" ]; then
        bk_path "$CERT_ROOT"
        if [ "$DRY" = "1" ]; then msg "[simulation] suppression de $CERT_ROOT"; else rm -rf "$CERT_ROOT"; fi
    fi
    if ! apache_test; then
        rollback_and_die
    fi
    reload_checked
    [ "$DRY" = "1" ] || bk_prune
    msg "Configuration HTTPS du plugin retirée (mod_ssl reste activé)."
    out result ok
    out removed 1
    out reload "$RELOAD_METHOD"
    [ -n "$BK_DIR" ] && out backup "$BK_DIR"
    out dryrun "$DRY"
    exit 0
}

action_status() {
    do_detect
    st_inst=0; st_conf=''; st_domain=''; st_alias=''; st_port=''; st_cert=''; st_redir=0; st_mode=''
    if [ "$WEBSERVER" = apache ] && [ -n "$CONF_SSL_L" ] && is_managed "$R$CONF_SSL_L"; then
        st_inst=1; st_mode=auto; st_conf="$CONF_SSL_L"
        st_domain=$(sed -n 's/^# Domaine : \([^ ]*\) .*/\1/p' "$R$CONF_SSL_L" | head -n 1)
        st_alias=$(sed -n 's/^# Alias : //p' "$R$CONF_SSL_L" | head -n 1)
        st_port=$(sed -n 's/^[[:space:]]*<VirtualHost[[:space:]]*\*:\([0-9]*\)>.*/\1/p' "$R$CONF_SSL_L" | head -n 1)
        st_cert=$(sed -n 's/^[[:space:]]*SSLCertificateFile[[:space:]]*//p' "$R$CONF_SSL_L" | head -n 1)
        if [ "$LAYOUT" = debian ] && [ ! -e "$R$AP_DIR/sites-enabled/$SSL_CONF_NAME.conf" ]; then
            st_inst=0
            msg "Le fichier $CONF_SSL_L existe mais le site n'est pas activé."
        fi
        is_managed "$R$CONF_REDIR_L" && st_redir=1
    elif [ "$WEBSERVER" = nginx ] && is_managed "$R$NGINX_SNIPPET_L"; then
        st_inst=1; st_mode=manual; st_conf="$NGINX_SNIPPET_L"
        st_cert=$(sed -n 's/^ssl_certificate[[:space:]]*\([^;]*\);.*/\1/p' "$R$NGINX_SNIPPET_L" | head -n 1)
        st_domain=$(basename "$(dirname "$st_cert")")
    fi
    out installed "$st_inst"
    out webserver "$WEBSERVER"
    out layout "$LAYOUT"
    out mode "$st_mode"
    out conf "$st_conf"
    out domain "$st_domain"
    out aliases "$st_alias"
    out port "$st_port"
    out redirect "$st_redir"
    out fullchain "$st_cert"
    if [ -n "$st_cert" ]; then
        out key "$(dirname "$st_cert")/privkey.pem"
        if [ -r "$R$st_cert" ] && st_ossl=$(tool_cmd openssl); then
            st_end=$("$st_ossl" x509 -in "$R$st_cert" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
            out cert_not_after "$st_end"
            st_subj=$("$st_ossl" x509 -in "$R$st_cert" -noout -subject 2>/dev/null | sed 's/^subject=[[:space:]]*//')
            out cert_subject "$st_subj"
            # date -d : GNU ; date -D : busybox. Facultatif.
            st_ts=$(date -d "$st_end" +%s 2>/dev/null) || st_ts=$(date -D '%b %e %H:%M:%S %Y' -d "${st_end% GMT}" +%s 2>/dev/null) || st_ts=''
            if [ -n "$st_ts" ]; then
                out cert_expires_ts "$st_ts"
                out days_left $(( (st_ts - $(date +%s)) / 86400 ))
            fi
        elif [ -n "$st_cert" ] && [ ! -r "$R$st_cert" ]; then
            msg "Certificat installé illisible (droits ?) : $R$st_cert"
        fi
    fi
    out result ok
    exit 0
}

usage() {
    cat >&2 <<'EOF'
Usage :
  acme_webserver.sh detect
  acme_webserver.sh install --domain D --fullchain F --key K [--alias NOM]... [--port 443]
                            [--redirect 0|1] [--redirect-port N] [--webroot /var/www/html]
                            [--force-port]
  acme_webserver.sh reload
  acme_webserver.sh uninstall
  acme_webserver.sh status
EOF
}

# ---------------------------------------------------------------------------

[ $# -ge 1 ] || { usage; die 2 "action manquante"; }
ACTION="$1"
shift
case "$ACTION" in
    detect)
        do_detect
        if [ "$(id -u)" != 0 ] && [ -z "$R" ]; then
            msg "Non root : détection partielle possible (processus des autres comptes sur le port 443)."
        fi
        print_detect
        out result ok
        exit 0 ;;
    install)   action_install "$@" ;;
    reload)    action_reload ;;
    uninstall) action_uninstall ;;
    status)    action_status ;;
    -h|--help|help) usage; exit 0 ;;
    *) usage; die 2 "action inconnue : $ACTION" ;;
esac

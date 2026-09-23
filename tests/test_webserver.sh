#!/bin/sh
# Tests de resources/acme_webserver.sh et de acmeInstaller — plugin Jeedom acme.
#
# Tout se passe dans une arborescence factice (ACME_ROOT) sous un dossier
# temporaire, avec de faux apache2ctl/apachectl/a2enmod/a2ensite/systemctl/nginx
# placés en tête du PATH : ils journalisent leurs appels dans calls.log et
# simulent le succès ou l'échec du test de configuration. Rien n'est écrit
# hors du dossier temporaire, aucun serveur web réel n'est touché.
#
# Usage : sh tests/test_webserver.sh   (TMPDIR : dossier temporaire ;
#         TEST_SHELL="busybox sh" : lancer le script sous un autre shell)

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../resources/acme_webserver.sh"
BASE=$(mktemp -d "${TMPDIR:-/tmp}/acme-test.XXXXXX") || exit 1
trap 'rm -rf "$BASE"' EXIT INT TERM
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
ko()   { FAIL=$((FAIL + 1)); printf '  ÉCHEC %s\n' "$1"; }
check() { # check "description" commande…
    cd_desc="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$cd_desc"; else ko "$cd_desc"; fi
}
title() { printf '\n== %s\n' "$1"; }

# Valeur d'une clé dans la dernière sortie ($OUT).
val() { printf '%s\n' "$OUT" | sed -n "s/^$1=//p" | head -n 1; }
is()  { [ "$(val "$1")" = "$2" ]; }
called() { grep -q -e "$1" "$ROOT/calls.log" 2>/dev/null; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# Lance le script dans la racine courante. Sortie : OUT, ERR, RC.
# Variables des faux binaires : FAKE_TEST (test de conf), FAKE_PATTERN,
# FAKE_RELOAD (die : Apache meurt après le rechargement, code 0 ; fail : le
# rechargement échoue, Apache reste), FAKE_START=fail, FAKE_CAT_FAIL et
# FAKE_MV_FAIL (motif : cat / mv échouent si un argument le contient),
# FAKE_SS_IGNORE (port qu'Apache n'écoute pas malgré son Listen).
run() {
    OUT=$(env ACME_ROOT="$ROOT" PATH="$ROOT/fakebin:$PATH" FAKE_TEST="${FAKE_TEST:-ok}" FAKE_PATTERN="${FAKE_PATTERN:-}" \
        FAKE_RELOAD="${FAKE_RELOAD:-}" FAKE_START="${FAKE_START:-}" FAKE_CAT_FAIL="${FAKE_CAT_FAIL:-}" \
        FAKE_MV_FAIL="${FAKE_MV_FAIL:-}" FAKE_SS_IGNORE="${FAKE_SS_IGNORE:-}" \
        ${TEST_SHELL:-sh} "$SCRIPT" "$@" 2>"$BASE/stderr")
    RC=$?
    ERR=$(cat "$BASE/stderr")
}

# Crée une racine factice : new_root nom os(debian|ubuntu|fedora|alpine|…) serveur(apache|nginx|none)
new_root() {
    ROOT="$BASE/$1"
    rm -rf "$ROOT"
    mkdir -p "$ROOT/etc" "$ROOT/fakebin" "$ROOT/var/www/html" "$ROOT/run/systemd/system" "$ROOT/proc/1"
    echo '0::/init.scope' > "$ROOT/proc/1/cgroup"
    : > "$ROOT/calls.log"
    case "$2" in
        debian) printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n' ;;
        ubuntu) printf 'PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n' ;;
        raspbian) printf 'PRETTY_NAME="Raspbian GNU/Linux 11"\nID=raspbian\nID_LIKE=debian\nVERSION_ID="11"\n' ;;
        fedora) printf 'NAME="Fedora Linux"\nID=fedora\nVERSION_ID=40\n' ;;
        rocky)  printf 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n' ;;
        alpine) printf 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.20.0\n' ;;
        suse)   printf 'NAME="openSUSE Leap"\nID="opensuse-leap"\nID_LIKE="suse opensuse"\nVERSION_ID="15.6"\n' ;;
        arch)   printf 'NAME="Arch Linux"\nID=arch\n' ;;
    esac > "$ROOT/etc/os-release"

    # Faux binaires : journalisent « nom args » dans calls.log.
    cat > "$ROOT/fakebin/_fake" <<'EOF'
#!/bin/sh
n=$(basename "$0")
A="$ACME_ROOT/etc/apache2"
P="$ACME_ROOT/proc/100"
# Outils courants détournés, non journalisés.
case "$n" in
    cat|mv)
        if [ "$n" = cat ]; then pat="${FAKE_CAT_FAIL:-}"; else pat="${FAKE_MV_FAIL:-}"; fi
        if [ -n "$pat" ]; then
            case "$*" in *"$pat"*) echo "$n: échec simulé" >&2; exit 1 ;; esac
        fi
        exec "/bin/$n" "$@" ;;
    ss)
        # Apache écoute les ports de ses Listen tant que son maître tourne.
        if [ -e "$P/comm" ]; then
            if [ -d "$A/sites-enabled" ]; then
                fl=$(cat "$A/ports.conf" "$A"/sites-enabled/* "$A"/conf-enabled/* 2>/dev/null)
            else
                fl=$(cat $(find "$ACME_ROOT/etc/apache2" "$ACME_ROOT/etc/httpd" -name '*.conf' 2>/dev/null) 2>/dev/null)
            fi
            printf '%s\n' "$fl" | sed -n 's/^[[:space:]]*Listen[[:space:]]\{1,\}\([^[:space:]]*:\)\{0,1\}\([0-9][0-9]*\).*/\2/p' | sort -u |
            while read -r p; do
                [ "$p" = "${FAKE_SS_IGNORE:-}" ] && continue
                echo "LISTEN 0 511 *:$p *:* users:((\"apache2\",pid=100,fd=4))"
            done
        fi
        [ -f "$ACME_ROOT/ss.extra" ] && cat "$ACME_ROOT/ss.extra"
        exit 0 ;;
esac
echo "$n $*" >> "$ACME_ROOT/calls.log"
last=''
for a in "$@"; do last="$a"; done
# Rechargement / démarrage : l'état d'Apache est /proc/100/comm.
case "$n $*" in
    "systemctl reload"*|"service "*" reload"|*" graceful")
        case "${FAKE_RELOAD:-}" in
            die) rm -rf "$P"; exit 0 ;;
            fail) exit 1 ;;
        esac
        exit 0 ;;
    "systemctl start"*|"service "*" start"|*" start")
        [ "${FAKE_START:-}" = fail ] && exit 1
        mkdir -p "$P"; echo apache2 > "$P/comm"; exit 0 ;;
esac
case "$n" in
    apache2ctl|apachectl|httpd)
        case "$1" in
            -v) echo "Server version: Apache/2.4.62 (Unix)"; exit 0 ;;
            -t)
                case "$FAKE_TEST" in
                    fail) echo "AH00526: Syntax error on line 1 (déjà cassé)" >&2; exit 1 ;;
                    fail_managed)
                        for f in "$A/sites-enabled/jeedom-acme-ssl.conf" "$ACME_ROOT/etc/httpd/conf.d/jeedom-acme-ssl.conf"; do
                            if [ -e "$f" ]; then
                                echo "AH00526: Syntax error on line 12 of $f: SSLCertificateFile: file does not exist" >&2
                                exit 1
                            fi
                        done ;;
                    fail_pattern)
                        if grep -rqs -e "$FAKE_PATTERN" "$ACME_ROOT/etc/apache2" "$ACME_ROOT/etc/httpd"; then
                            echo "AH00526: Syntax error: motif $FAKE_PATTERN refusé" >&2
                            exit 1
                        fi ;;
                esac
                echo "Syntax OK" >&2; exit 0 ;;
        esac
        exit 0 ;;
    a2enmod)
        if [ -d "$A/mods-enabled" ]; then
            ln -sf "../mods-available/$last.load" "$A/mods-enabled/$last.load"
        elif [ -f "$ACME_ROOT/etc/sysconfig/apache2" ]; then
            sed -i "s/^APACHE_MODULES=\"\(.*\)\"/APACHE_MODULES=\"\1 $last\"/" "$ACME_ROOT/etc/sysconfig/apache2"
        fi ;;
    a2enflag)
        sed -i "s/^APACHE_SERVER_FLAGS=\"\(.*\)\"/APACHE_SERVER_FLAGS=\"\1 $last\"/" "$ACME_ROOT/etc/sysconfig/apache2" ;;
    a2dismod) rm -f "$A/mods-enabled/$last.load" ;;
    a2ensite) ln -sf "../sites-available/$last.conf" "$A/sites-enabled/$last.conf" ;;
    a2dissite) rm -f "$A/sites-enabled/$last.conf" ;;
    a2enconf) ln -sf "../conf-available/$last.conf" "$A/conf-enabled/$last.conf" ;;
    a2disconf) rm -f "$A/conf-enabled/$last.conf" ;;
    nginx) [ "$1" = "-v" ] && echo "nginx version: nginx/1.24.0" >&2 ;;
esac
exit 0
EOF
    chmod +x "$ROOT/fakebin/_fake"
    for b in systemctl service a2enmod a2dismod a2ensite a2dissite a2enconf a2disconf a2enflag ss cat mv; do
        ln -s _fake "$ROOT/fakebin/$b"
    done

    case "$3" in
        apache)
            mkdir -p "$ROOT/proc/100" "$ROOT/run/apache2"; echo apache2 > "$ROOT/proc/100/comm"
            echo 100 > "$ROOT/run/apache2/apache2.pid"
            case "$2" in
                fedora|rocky|arch)
                    ln -s _fake "$ROOT/fakebin/apachectl"
                    mkdir -p "$ROOT/etc/httpd/conf.d" "$ROOT/etc/httpd/conf.modules.d" "$ROOT/etc/httpd/conf"
                    printf 'ServerRoot "/etc/httpd"\nListen 80\nIncludeOptional conf.d/*.conf\n' > "$ROOT/etc/httpd/conf/httpd.conf"
                    ;;
                alpine|suse)
                    ln -s _fake "$ROOT/fakebin/apachectl"
                    mkdir -p "$ROOT/etc/apache2/conf.d" "$ROOT/etc/apache2/vhosts.d"
                    printf 'Listen 80\nInclude /etc/apache2/conf.d/*.conf\n' > "$ROOT/etc/apache2/httpd.conf"
                    ;;
                *)
                    ln -s _fake "$ROOT/fakebin/apache2ctl"
                    A="$ROOT/etc/apache2"
                    mkdir -p "$A/mods-available" "$A/mods-enabled" "$A/sites-available" "$A/sites-enabled" \
                             "$A/conf-available" "$A/conf-enabled"
                    for m in ssl alias rewrite headers socache_shmcb; do echo "LoadModule ${m}_module x" > "$A/mods-available/$m.load"; done
                    ln -s ../mods-available/alias.load "$A/mods-enabled/alias.load"
                    printf 'Listen 80\n\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n' > "$A/ports.conf"
                    printf 'IncludeOptional sites-enabled/*.conf\n' > "$A/apache2.conf"
                    printf '<VirtualHost *:80>\n\tServerAdmin webmaster@localhost\n\tDocumentRoot /var/www/html\n</VirtualHost>\n' > "$A/sites-available/000-default.conf"
                    ln -s ../sites-available/000-default.conf "$A/sites-enabled/000-default.conf"
                    ;;
            esac ;;
        nginx)
            ln -s _fake "$ROOT/fakebin/nginx"
            mkdir -p "$ROOT/proc/200" "$ROOT/etc/nginx/sites-enabled"
            echo nginx > "$ROOT/proc/200/comm"
            echo 'server { listen 80; root /var/www/html; }' > "$ROOT/etc/nginx/sites-enabled/default"
            ;;
    esac
}

# Certificat et clé de test (autosignés), plus une autre clé pour le cas « ne correspond pas ».
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$BASE/key.pem" -out "$BASE/cert.pem" \
    -days 30 -subj /CN=jeedom.example.com >/dev/null 2>&1 || { echo "openssl requis"; exit 1; }
openssl genrsa -out "$BASE/other.pem" 2048 >/dev/null 2>&1
CERT="$BASE/cert.pem"
KEY="$BASE/key.pem"
# Seconde paire, même nom : pour distinguer l'ancien certificat du nouveau.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$BASE/key2.pem" -out "$BASE/cert2.pem" \
    -days 30 -subj /CN=jeedom.example.com >/dev/null 2>&1
CERT2="$BASE/cert2.pem"
KEY2="$BASE/key2.pem"
# Certificat à plusieurs noms (SAN), pour acmeInstaller.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$BASE/key3.pem" -out "$BASE/cert3.pem" -days 30 \
    -subj /CN=example.com -addext 'subjectAltName=DNS:*.example.com,DNS:www.example.com' >/dev/null 2>&1

# ---------------------------------------------------------------------------
title "Syntaxe POSIX"
check "sh -n" sh -n "$SCRIPT"
if command -v dash >/dev/null 2>&1; then check "dash -n" dash -n "$SCRIPT"; fi
if command -v busybox >/dev/null 2>&1; then check "busybox ash -n" busybox sh -n "$SCRIPT"; fi
if command -v checkbashisms >/dev/null 2>&1; then check "checkbashisms" checkbashisms "$SCRIPT"; fi
if command -v shellcheck >/dev/null 2>&1; then check "shellcheck -s sh" shellcheck -s sh -S error "$SCRIPT"; fi

# ---------------------------------------------------------------------------
title "detect"
for os in debian ubuntu raspbian; do
    new_root "det-$os" "$os" apache; run detect
    check "$os : layout debian, apache, supporté" test "$RC:$(val layout):$(val webserver):$(val supported)" = "0:debian:apache:1"
    case "$os" in
        debian) check "debian : systemd=1 docker=0 ssl_module=1 ssl_enabled=0" test "$(val systemd)$(val docker)$(val ssl_module)$(val ssl_enabled)" = "1010" ;;
        ubuntu) check "ubuntu : os_id ubuntu, os_version 24.04" test "$(val os_id):$(val os_version)" = "ubuntu:24.04" ;;
    esac
done

new_root det-fedora fedora apache; run detect
check "fedora : layout rhel, apache" test "$(val layout):$(val webserver)" = "rhel:apache"
check "fedora sans mod_ssl : supported=0, raison dnf install mod_ssl" test "$(val supported)" = 0 -a -n "$(val reason | grep 'dnf install mod_ssl')"
new_root det-rocky rocky apache; : > "$ROOT/etc/httpd/conf.modules.d/00-ssl.conf"; run detect
check "rocky (ID_LIKE rhel) avec mod_ssl : supporté" test "$(val layout):$(val ssl_module):$(val supported)" = "rhel:1:1"

new_root det-alpine alpine apache; run detect
check "alpine sans apache2-ssl : non supporté, apk add apache2-ssl" test "$(val layout):$(val supported)" = "alpine:0" -a -n "$(val reason | grep 'apk add apache2-ssl')"
: > "$ROOT/etc/apache2/conf.d/ssl.conf"; run detect
check "alpine avec conf.d/ssl.conf : supporté" test "$(val ssl_module):$(val supported)" = "1:1"

new_root det-suse suse apache; run detect
check "opensuse : layout suse" is layout suse
new_root det-arch arch apache; mkdir -p "$ROOT/usr/lib/httpd/modules"; : > "$ROOT/usr/lib/httpd/modules/mod_ssl.so"; run detect
check "arch : conf.d trouvé via IncludeOptional, supporté" test "$(val layout):$(val conf_dir):$(val supported)" = "arch:/etc/httpd/conf.d:1"

new_root det-docker debian apache; rm -rf "$ROOT/run/systemd"; touch "$ROOT/.dockerenv"; run detect
check "docker : docker=1 systemd=0" test "$(val docker)$(val systemd)" = "10"
new_root det-nginx debian nginx; run detect
check "nginx : webserver nginx, mode manual" test "$(val webserver):$(val mode):$(val supported)" = "nginx:manual:1"
new_root det-none debian none; run detect
check "rien : unknown, supported=0" test "$(val webserver):$(val supported)" = "unknown:0"
rm -f "$ROOT/fakebin/ss"; run detect
check "port 443 inconnu en ACME_ROOT (ss du système ignoré)" is port443_used unknown

# ---------------------------------------------------------------------------
title "install Debian"
new_root deb debian apache
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
A="$ROOT/etc/apache2"
D="$ROOT/etc/ssl/jeedom-acme/jeedom.example.com"
check "code 0, result=ok, mode=auto" test "$RC:$(val result):$(val mode)" = "0:ok:auto"
check "fullchain copié en 0644" test "$(mode_of "$D/fullchain.pem")" = 644
check "clé copiée en 0600" test "$(mode_of "$D/privkey.pem")" = 600
check "dossier du certificat en 0700" test "$(mode_of "$D")" = 700
check "contenu du certificat identique" cmp "$CERT" "$D/fullchain.pem"
check "a2enmod ssl appelé" called '^a2enmod -q ssl$'
check "alias déjà actif : pas de a2enmod alias" test -z "$(grep 'a2enmod.*alias' "$ROOT/calls.log")"
check "a2ensite jeedom-acme-ssl appelé" called '^a2ensite -q jeedom-acme-ssl$'
check "test de configuration appelé" called '^apache2ctl -t$'
check "systemctl reload apache2 appelé" called '^systemctl reload apache2$'
check "reload=systemctl reload apache2" is reload "systemctl reload apache2"
C="$A/sites-available/jeedom-acme-ssl.conf"
check "vhost : marqueur" grep -q 'géré par le plugin Jeedom acme' "$C"
check "vhost : <VirtualHost *:443>" grep -q '<VirtualHost \*:443>' "$C"
check "vhost : ServerName" grep -q 'ServerName jeedom.example.com' "$C"
check "vhost : DocumentRoot" grep -q 'DocumentRoot /var/www/html' "$C"
check "vhost : AllowOverride All (vhost 80 sans Directory)" grep -q 'AllowOverride All' "$C"
check "vhost : SSLCertificateFile hors du dossier du plugin" grep -q 'SSLCertificateFile /etc/ssl/jeedom-acme/jeedom.example.com/fullchain.pem' "$C"
check "vhost : SSLCertificateKeyFile" grep -q 'SSLCertificateKeyFile /etc/ssl/jeedom-acme/jeedom.example.com/privkey.pem' "$C"
check "vhost : TLS 1.2 minimum" grep -q 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1' "$C"
check "port 443 : pas de Listen ajouté (ports.conf l'a)" test -z "$(grep Listen "$C")"
check "000-default.conf intact" test "$(cat "$A/sites-available/000-default.conf" | wc -l)" -eq 4
check "sauvegarde créée" test -d "$(val backup)"

title "status"
run status
check "installed=1, domaine, port 443" test "$(val installed):$(val domain):$(val port)" = "1:jeedom.example.com:443"
check "date d'expiration lue par openssl" test -n "$(val cert_not_after)"
check "days_left ≈ 29-30" test "$(val days_left)" -ge 29

title "idempotence"
: > "$ROOT/calls.log"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "2e install : code 0" test "$RC" = 0
check "2e install : ni a2enmod ni a2ensite (déjà actifs)" test -z "$(grep -e a2enmod -e a2ensite "$ROOT/calls.log")"
check "2e install : test puis reload" test "$(tr '\n' ';' < "$ROOT/calls.log")" = "apache2ctl -v;apache2ctl -t;apache2ctl -t;systemctl reload apache2;"
check "un seul VirtualHost dans le fichier" test "$(grep -c '<VirtualHost' "$C")" = 1

title "changement de domaine : ancien dossier de certificat retiré"
run install --domain '*.example.com' --fullchain "$CERT" --key "$KEY"
check "wildcard : code 0" test "$RC" = 0
check "wildcard : dossier example.com" test -f "$ROOT/etc/ssl/jeedom-acme/example.com/privkey.pem"
check "ancien dossier jeedom.example.com supprimé" test ! -e "$D"
check "wildcard : ServerName example.com + ServerAlias *.example.com" test -n "$(grep 'ServerName example.com' "$C")" -a -n "$(grep 'ServerAlias \*.example.com' "$C")"

title "redirection"
: > "$ROOT/calls.log"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 1
RD="$A/conf-available/jeedom-acme-redirect.conf"
check "code 0, conf_redirect" test "$RC:$(val conf_redirect)" = "0:/etc/apache2/conf-available/jeedom-acme-redirect.conf"
check "a2enconf jeedom-acme-redirect appelé" called '^a2enconf -q jeedom-acme-redirect$'
check "redirect : marqueur" grep -q 'géré par le plugin Jeedom acme' "$RD"
check "redirect : exclut /.well-known/acme-challenge/" grep -q 'REQUEST_URI} !~ m#^/\\.well-known/acme-challenge/#' "$RD"
check "redirect : limitée au nom du certificat" grep -q 'HTTP_HOST} =~ m#^(jeedom\\.example\\.com)(:\[0-9\]+)?\$#i' "$RD"
check "redirect : via <If> HTTPS != on" grep -q "<If \"%{HTTPS} != 'on'" "$RD"
check "redirect : Redirect temp vers https" grep -q 'Redirect temp "https://%{SERVER_NAME}%{REQUEST_URI}"' "$RD"
: > "$ROOT/calls.log"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 1 --redirect-port 9003
check "redirect-port 9003 : cible https://nom:9003 (port public du routeur)" grep -q 'Redirect temp "https://%{SERVER_NAME}:9003%{REQUEST_URI}"' "$RD"
check "redirect-port 9003 : sortie redirect_port=9003, port local inchangé" test "$(val redirect_port):$(val port)" = "9003:443"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 1 --redirect-port abc
check "redirect-port invalide : code 2" test "$RC" = 2
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 1
check "sans redirect-port : retour à https://nom (443)" grep -q 'Redirect temp "https://%{SERVER_NAME}%{REQUEST_URI}"' "$RD"

run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 0
check "redirect=0 ensuite : a2disconf + fichier supprimé" test "$RC" = 0 -a ! -e "$RD" -a -n "$(grep '^a2disconf -q jeedom-acme-redirect' "$ROOT/calls.log")"

title "port 8443"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8443
check "code 0, listen_added=1" test "$RC:$(val listen_added)" = "0:1"
check "Listen 8443 https dans <IfModule mod_ssl.c>" test "$(sed -n '/<IfModule mod_ssl.c>/{n;p;}' "$C" | tr -d ' ')" = "Listen8443https"
check "<VirtualHost *:8443>" grep -q '<VirtualHost \*:8443>' "$C"
run status
check "status : port 8443" is port 8443

title "uninstall"
: > "$ROOT/calls.log"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 1 >/dev/null
: > "$ROOT/calls.log"
run uninstall
check "code 0, removed=1" test "$RC:$(val removed)" = "0:1"
check "a2dissite et a2disconf appelés" test -n "$(grep '^a2dissite -q jeedom-acme-ssl' "$ROOT/calls.log")" -a -n "$(grep '^a2disconf -q jeedom-acme-redirect' "$ROOT/calls.log")"
check "mod_ssl laissé activé (pas de a2dismod)" test -z "$(grep a2dismod "$ROOT/calls.log")" -a -e "$A/mods-enabled/ssl.load"
check "fichiers gérés supprimés" test ! -e "$C" -a ! -e "$RD" -a ! -e "$ROOT/etc/ssl/jeedom-acme"
check "reload après désinstallation" called '^systemctl reload apache2$'
run status
check "status : installed=0" is installed 0
run uninstall
check "2e uninstall : rien à faire, code 0" test "$RC:$(val removed)" = "0:0"

title "échec du test de configuration → restauration"
new_root debfail debian apache
A="$ROOT/etc/apache2"
FAKE_TEST=fail_managed run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 1 --port 8443
check "code 6" test "$RC" = 6
check "message clair avec la sortie du test" test -n "$(val error | grep 'AH00526')"
check "a2dismod ssl appelé" called 'a2dismod -q -f ssl'
check "a2dissite jeedom-acme-ssl appelé" called 'a2dissite -q jeedom-acme-ssl'
check "a2disconf jeedom-acme-redirect appelé" called 'a2disconf -q jeedom-acme-redirect'
check "aucun fichier géré restant" test -z "$(grep -rl 'géré par le plugin Jeedom acme' "$ROOT/etc" 2>/dev/null)"
check "aucun certificat restant" test ! -e "$ROOT/etc/ssl/jeedom-acme"
check "ssl désactivé, alias toujours actif" test ! -e "$A/mods-enabled/ssl.load" -a -e "$A/mods-enabled/alias.load"
check "pas de reload" test -z "$(grep -e reload -e graceful "$ROOT/calls.log")"

title "échec sur une mise à jour → l'ancienne version revient"
FAKE_TEST=ok run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
cp "$A/sites-available/jeedom-acme-ssl.conf" "$BASE/before.conf"
FAKE_TEST=fail_pattern FAKE_PATTERN=autre.example.com run install --domain autre.example.com --fullchain "$CERT" --key "$KEY" --port 8443
check "code 6" test "$RC" = 6
check "fichier du vhost restauré à l'identique" cmp "$BASE/before.conf" "$A/sites-available/jeedom-acme-ssl.conf"
check "site toujours activé" test -L "$A/sites-enabled/jeedom-acme-ssl.conf"
check "ancien certificat restauré, nouveau absent" test -f "$ROOT/etc/ssl/jeedom-acme/jeedom.example.com/privkey.pem" -a ! -e "$ROOT/etc/ssl/jeedom-acme/autre.example.com"
check "mod_ssl (déjà actif avant) non désactivé" test -e "$A/mods-enabled/ssl.load"

title "configuration déjà cassée avant install"
new_root debbroken debian apache
FAKE_TEST=fail run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "code 8, rien écrit, rien activé" test "$RC" = 8 -a ! -e "$ROOT/etc/ssl/jeedom-acme" -a -z "$(grep a2en "$ROOT/calls.log")"

title "vhost 80 avec <Directory> : directives reprises"
new_root debdir debian apache
A="$ROOT/etc/apache2"
printf '<VirtualHost *:80>\n  DocumentRoot /var/www/html\n  <Directory /var/www/html/>\n    Options FollowSymLinks\n    AllowOverride All\n    Require all granted\n  </Directory>\n</VirtualHost>\n' > "$A/sites-available/000-default.conf"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
C="$A/sites-available/jeedom-acme-ssl.conf"
check "code 0" test "$RC" = 0
check "Options FollowSymLinks repris" grep -q 'Options FollowSymLinks' "$C"
check "un seul bloc <Directory> (pas de doublon)" test "$(grep -c '<Directory' "$C")" = 1

title "arguments invalides"
new_root args debian apache
run install --domain 'bad domain;rm' --fullchain "$CERT" --key "$KEY"
check "domaine invalide : code 2" test "$RC" = 2
run install --domain 'a.b"c' --fullchain "$CERT" --key "$KEY"
check "guillemet dans le domaine : code 2" test "$RC" = 2
run install --domain jeedom.example.com --fullchain /nope --key "$KEY"
check "fullchain absent : code 2" test "$RC" = 2
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 44x
check "port non numérique : code 2" test "$RC" = 2
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 80
check "port 80 refusé : code 2" test "$RC" = 2
run install --domain jeedom.example.com --fullchain "$CERT" --key "$BASE/other.pem"
check "clé ≠ certificat : code 2" test "$RC" = 2 -a -n "$(val error | grep 'ne correspond pas')"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --webroot '/var/www/x y'
check "webroot avec espace : code 2" test "$RC" = 2
check "rien d'écrit après les refus" test ! -e "$ROOT/etc/ssl/jeedom-acme"

title "non root sans ACME_ROOT ni ACME_DRYRUN"
if [ "$(id -u)" != 0 ]; then
    OUT=$(env -u ACME_ROOT -u ACME_DRYRUN sh "$SCRIPT" install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" 2>/dev/null); RC=$?
    check "code 3" test "$RC" = 3
else
    echo "  (ignoré : lancé en root)"
fi

title "Docker sans systemd → apache2ctl graceful"
new_root docker debian apache
rm -rf "$ROOT/run/systemd"; touch "$ROOT/.dockerenv"; mkdir -p "$ROOT/etc/init.d"; : > "$ROOT/etc/init.d/apache2"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "code 0, reload=apache2ctl graceful" test "$RC:$(val reload)" = "0:apache2ctl graceful"
check "apache2ctl graceful appelé, pas systemctl ni service" test -n "$(grep '^apache2ctl graceful' "$ROOT/calls.log")" -a -z "$(grep -e '^systemctl' -e '^service' "$ROOT/calls.log")"

title "Apache arrêté → pas de rechargement"
new_root stopped debian apache
rm -rf "$ROOT/proc/100"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "code 0, reload=skipped" test "$RC:$(val reload)" = "0:skipped"

title "nginx → mode manuel"
new_root ngx debian nginx
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
S="$ROOT/etc/nginx/snippets/jeedom-acme-ssl.conf"
check "code 0, mode=manual, included=0" test "$RC:$(val mode):$(val included)" = "0:manual:0"
check "fragment avec ssl_certificate" grep -q 'ssl_certificate /etc/ssl/jeedom-acme/jeedom.example.com/fullchain.pem;' "$S"
check "fragment avec marqueur" grep -q 'géré par le plugin Jeedom acme' "$S"
check "exemple de bloc server sur stderr" test -n "$(printf '%s' "$ERR" | grep 'include /etc/nginx/snippets/jeedom-acme-ssl.conf;')"
check "fragment : data/ du plugin interdit" grep -q -x 'location ^~ /plugins/acme/data/ { deny all; }' "$S"
check "instructions affichées : data/ interdit" test -n "$(printf '%s' "$ERR" | grep 'location ^~ /plugins/acme/data/ { deny all; }')" -a -n "$(val instructions | grep 'location ^~ /plugins/acme/data/ { deny all; }')"
run install --domain jeedom.example.com --alias www.example.com --fullchain "$CERT" --key "$KEY"
check "nginx : server_name avec tous les noms" test -n "$(printf '%s' "$ERR" | grep 'server_name jeedom.example.com www.example.com;')"
check "server existant intact" test "$(cat "$ROOT/etc/nginx/sites-enabled/default")" = 'server { listen 80; root /var/www/html; }'
check "pas de reload (fragment non inclus)" test -z "$(grep -e reload "$ROOT/calls.log")"
echo 'server { listen 443 ssl; include /etc/nginx/snippets/jeedom-acme-ssl.conf; }' > "$ROOT/etc/nginx/sites-enabled/ssl"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "fragment inclus : nginx -t puis reload (renouvellement automatique)" test "$(val included):$RC" = "1:0" -a -n "$(grep '^nginx -t' "$ROOT/calls.log")" -a -n "$(grep '^systemctl reload nginx' "$ROOT/calls.log")"
run status
check "status nginx : installed=1 mode=manual" test "$(val installed):$(val mode):$(val domain)" = "1:manual:jeedom.example.com"
run uninstall
check "uninstall nginx refusé tant que le fragment est inclus" test "$RC" = 1

title "RHEL"
new_root rh rocky apache
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "sans mod_ssl : code 5" test "$RC" = 5
check "message « dnf install mod_ssl »" test -n "$(val error | grep 'dnf install mod_ssl')"
check "rien écrit" test ! -e "$ROOT/etc/ssl/jeedom-acme" -a ! -e "$ROOT/etc/httpd/conf.d/jeedom-acme-ssl.conf"
: > "$ROOT/etc/httpd/conf.modules.d/00-ssl.conf"
printf 'Listen 443 https\n<VirtualHost _default_:443>\nSSLEngine on\n</VirtualHost>\n' > "$ROOT/etc/httpd/conf.d/ssl.conf"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 1
check "avec mod_ssl : code 0, conf.d" test "$RC:$(val conf_ssl)" = "0:/etc/httpd/conf.d/jeedom-acme-ssl.conf"
check "Listen 443 déjà dans ssl.conf : pas de doublon" test "$(val listen_added)" = 0
check "logs relatifs à ServerRoot" grep -q 'ErrorLog logs/jeedom-acme-ssl_error.log' "$ROOT/etc/httpd/conf.d/jeedom-acme-ssl.conf"
check "redirection dans conf.d" test -f "$ROOT/etc/httpd/conf.d/jeedom-acme-redirect.conf"
check "systemctl reload httpd" called '^systemctl reload httpd$'
FAKE_TEST=fail_pattern FAKE_PATTERN=8443 run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8443
check "rhel échec → code 6 et ancienne conf (443) restaurée" test "$RC" = 6 -a -n "$(grep '<VirtualHost \*:443>' "$ROOT/etc/httpd/conf.d/jeedom-acme-ssl.conf")"

title "arch : LoadModule conditionnel"
new_root ar arch apache
mkdir -p "$ROOT/usr/lib/httpd/modules"; : > "$ROOT/usr/lib/httpd/modules/mod_ssl.so"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "code 0, LoadModule ssl_module dans <IfModule !mod_ssl.c>" test "$RC" = 0 -a -n "$(grep 'LoadModule ssl_module /usr/lib/httpd/modules/mod_ssl.so' "$ROOT/etc/httpd/conf.d/jeedom-acme-ssl.conf")"
check "Listen 443 ajouté (absent de httpd.conf)" is listen_added 1

# ---------------------------------------------------------------------------
title "certificat et clé : jamais une paire désassortie"
new_root pair debian apache
D="$ROOT/etc/ssl/jeedom-acme/jeedom.example.com"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "installation initiale : code 0" test "$RC" = 0
: > "$ROOT/calls.log"
FAKE_CAT_FAIL="$KEY2" run install --domain jeedom.example.com --fullchain "$CERT2" --key "$KEY2"
check "copie de la clé en échec : code 1, message" test "$RC" = 1 -a -n "$(val error | grep 'copie de la clé impossible')"
check "ancienne paire intacte (certificat)" cmp "$CERT" "$D/fullchain.pem"
check "ancienne paire intacte (clé)" cmp "$KEY" "$D/privkey.pem"
check "aucun fichier temporaire restant" test -z "$(ls -A "$D" | grep -v -x -e fullchain.pem -e privkey.pem)"
check "pas de rechargement" test -z "$(grep -e reload -e graceful "$ROOT/calls.log")"
FAKE_MV_FAIL=privkey.pem run install --domain jeedom.example.com --fullchain "$CERT2" --key "$KEY2"
check "mv de la clé en échec (certificat déjà en place) : code 1" test "$RC" = 1 -a -n "$(val error | grep 'mise en place de la clé')"
check "certificat restauré avec sa clé" cmp "$CERT" "$D/fullchain.pem"
check "clé d'origine restaurée" cmp "$KEY" "$D/privkey.pem"
check "clé toujours en 0600" test "$(mode_of "$D/privkey.pem")" = 600
check "vhost toujours présent et actif" test -L "$ROOT/etc/apache2/sites-enabled/jeedom-acme-ssl.conf"
new_root pair2 debian apache
FAKE_MV_FAIL=privkey.pem run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "1re installation, mv de la clé en échec : code 1, rien ne reste" test "$RC" = 1 -a ! -e "$ROOT/etc/ssl/jeedom-acme"
check "1re installation : rien activé" test -z "$(grep a2en "$ROOT/calls.log")"
run install --domain jeedom.example.com --fullchain "$CERT2" --key "$KEY2"
check "ensuite, installation normale : nouvelle paire en place" test "$RC" = 0 -a -n "$(cmp "$CERT2" "$ROOT/etc/ssl/jeedom-acme/jeedom.example.com/fullchain.pem" && echo same)"

# ---------------------------------------------------------------------------
title "Apache meurt après le rechargement → restauration et redémarrage"
new_root dies debian apache
A="$ROOT/etc/apache2"
FAKE_RELOAD=die run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8443 --redirect 1
check "code 11" test "$RC" = 11
check "message : arrêté, restauré, relancé" test -n "$(val error | grep 'restauré et Apache relancé')"
check "systemctl start apache2 appelé" called '^systemctl start apache2$'
check "restart=systemctl start apache2" is restart "systemctl start apache2"
check "Apache tourne de nouveau" test -e "$ROOT/proc/100/comm"
check "a2dismod ssl et headers, a2dissite, a2disconf" test -n "$(grep '^a2dismod -q -f ssl' "$ROOT/calls.log")" -a -n "$(grep '^a2dismod -q -f headers' "$ROOT/calls.log")" -a -n "$(grep '^a2dissite -q jeedom-acme-ssl' "$ROOT/calls.log")" -a -n "$(grep '^a2disconf -q jeedom-acme-redirect' "$ROOT/calls.log")"
check "aucun fichier géré ni certificat restant" test -z "$(grep -rl 'géré par le plugin Jeedom acme' "$ROOT/etc" 2>/dev/null)" -a ! -e "$ROOT/etc/ssl/jeedom-acme"
check "mod_alias (actif avant) laissé" test -e "$A/mods-enabled/alias.load"
FAKE_RELOAD=die FAKE_START=fail run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8443
check "redémarrage impossible : code 9, intervention manuelle" test "$RC" = 9 -a -n "$(val error | grep 'intervention manuelle')"
mkdir -p "$ROOT/proc/100"; echo apache2 > "$ROOT/proc/100/comm"
: > "$ROOT/calls.log"
FAKE_SS_IGNORE=8443 run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8443
check "Apache vivant mais n'écoute pas le port : code 11, ancienne conf rechargée" test "$RC:$(val restart)" = "11:systemctl reload apache2" -a -n "$(val error | grep "n'écoute pas sur le port 8443")"
check "…sans démarrage superflu" test -z "$(grep 'start' "$ROOT/calls.log")"
: > "$ROOT/calls.log"
FAKE_RELOAD=fail run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "rechargement refusé mais Apache vivant : code 7" test "$RC" = 7
FAKE_RELOAD=die run reload
check "reload seul, Apache meurt : code 7, relancé" test "$RC" = 7 -a -n "$(val error | grep 'relancé par')" -a -e "$ROOT/proc/100/comm"
new_root dies-docker debian apache
rm -rf "$ROOT/run/systemd" "$ROOT/run/apache2"; touch "$ROOT/.dockerenv"
FAKE_RELOAD=die run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "docker sans fichier PID : code 11, relancé par apache2ctl start" test "$RC:$(val restart)" = "11:apache2ctl start"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "docker : installation normale ensuite, code 0" test "$RC" = 0
FAKE_RELOAD=die run uninstall
check "uninstall puis Apache meurt : code 11, configuration remise" test "$RC" = 11 -a -f "$ROOT/etc/apache2/sites-available/jeedom-acme-ssl.conf" -a -f "$ROOT/etc/ssl/jeedom-acme/jeedom.example.com/privkey.pem"

# ---------------------------------------------------------------------------
title "port : libre inconnu, pris, déjà servi en HTTP"
new_root port debian apache
A="$ROOT/etc/apache2"
rm -f "$ROOT/fakebin/ss"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8443
check "ni ss ni netstat + Listen à ajouter : code 12, rien écrit" test "$RC" = 12 -a ! -e "$ROOT/etc/ssl/jeedom-acme" -a -n "$(val error | grep -e '--force-port')"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "port 443 (Listen déjà présent) : accepté sans ss" test "$RC" = 0
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8443 --force-port
check "--force-port : code 0, avertissement" test "$RC" = 0 -a -n "$(printf '%s' "$ERR" | grep 'installation forcée')"
ln -s _fake "$ROOT/fakebin/ss"
echo 'LISTEN 0 128 0.0.0.0:9443 0.0.0.0:* users:(("node",pid=5,fd=3))' > "$ROOT/ss.extra"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 9443
check "port pris par un autre programme : code 10" test "$RC" = 10 -a -n "$(val error | grep node)"
printf 'Listen 8080\n' >> "$A/ports.conf"
printf '<VirtualHost *:8080>\n\tDocumentRoot /var/www/html\n</VirtualHost>\n' > "$A/sites-available/web8080.conf"
ln -s ../sites-available/web8080.conf "$A/sites-enabled/web8080.conf"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8080
check "port déjà servi en HTTP par Apache : code 10, fichier cité" test "$RC" = 10 -a -n "$(val error | grep 'web8080.conf')"
printf '<VirtualHost 192.168.1.2:8080>\n\tSSLEngine on\n</VirtualHost>\n' > "$A/sites-available/web8080.conf"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --port 8080
check "port servi par un VirtualHost TLS : accepté (code 0, pas de Listen ajouté)" test "$RC:$(val listen_added)" = "0:0"

# ---------------------------------------------------------------------------
title "retours à la ligne et chemins hostiles"
new_root inj debian apache
NL='
'
run install --domain "jeedom.example.com${NL}Include /etc/passwd" --fullchain "$CERT" --key "$KEY"
check "domaine + retour à la ligne : code 2" test "$RC" = 2
run install --domain "jeedom.example.com$(printf '\r')" --fullchain "$CERT" --key "$KEY"
check "domaine + CR : code 2" test "$RC" = 2
run install --domain jeedom.example.com --alias "www.example.com${NL}SSLEngine off" --fullchain "$CERT" --key "$KEY"
check "alias + retour à la ligne : code 2" test "$RC" = 2
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --webroot "/var/www/html${NL}/etc"
check "webroot + retour à la ligne : code 2" test "$RC" = 2
mkdir -p "$ROOT/etc/x"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --webroot "/var/www/../../etc/x"
check "webroot avec .. : code 2" test "$RC" = 2
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --webroot "/var//www/html"
check "webroot avec // : code 2" test "$RC" = 2
run install --domain '../../etc.example.com' --fullchain "$CERT" --key "$KEY"
check "domaine avec ../ : code 2" test "$RC" = 2
run install --domain 'a..example.com' --fullchain "$CERT" --key "$KEY"
check "domaine avec .. : code 2" test "$RC" = 2
check "rien d'écrit" test ! -e "$ROOT/etc/ssl/jeedom-acme" -a -z "$(grep a2en "$ROOT/calls.log")"

# ---------------------------------------------------------------------------
title "alias et jokers"
new_root names debian apache
A="$ROOT/etc/apache2"
C="$A/sites-available/jeedom-acme-ssl.conf"
RD="$A/conf-available/jeedom-acme-redirect.conf"
# Un fichier dont le nom correspond au joker : il ne doit pas le remplacer.
mkdir -p "$BASE/cwd"; : > "$BASE/cwd/piege.example.com"
OLDPWD_T=$(pwd); cd "$BASE/cwd"
run install --domain jeedom.example.com --alias WWW.example.com --alias '*.example.com' --alias jeedom.example.com --alias www.example.com \
    --fullchain "$CERT" --key "$KEY" --redirect 1
cd "$OLDPWD_T"
check "code 0, aliases=www.example.com *.example.com" test "$RC:$(val aliases)" = "0:www.example.com *.example.com"
check "ServerName jeedom.example.com" grep -q 'ServerName jeedom.example.com$' "$C"
check "une ServerAlias par alias, sans doublon ni nom principal" test "$(grep -c 'ServerAlias' "$C"):$(grep -c 'ServerAlias www.example.com$' "$C"):$(grep -c 'ServerAlias \*\.example\.com$' "$C")" = "2:1:1"
check "joker non développé en nom de fichier" test -z "$(grep piege "$C" "$RD")"
check "redirection : tous les noms" grep -q 'HTTP_HOST} =~ m#^(jeedom\\.example\\.com|www\\.example\\.com|\[^.\]+\\.example\\.com)(:\[0-9\]+)?\$#i' "$RD"
run status
check "status : aliases" is aliases "www.example.com *.example.com"
run install --domain '*.example.com' --fullchain "$CERT" --key "$KEY" --redirect 1
check "principal joker seul : ServerName nu, ServerAlias joker" test "$RC" = 0 -a -n "$(grep 'ServerName example.com$' "$C")" -a -n "$(grep 'ServerAlias \*\.example\.com$' "$C")"
check "principal joker seul : la redirection ne vise pas le nom nu" grep -q 'HTTP_HOST} =~ m#^(\[^.\]+\\.example\\.com)(:' "$RD"
run install --domain '*.example.com' --alias example.com --fullchain "$CERT" --key "$KEY" --redirect 1
check "joker + nom nu en alias : redirection des deux" grep -q 'HTTP_HOST} =~ m#^(\[^.\]+\\.example\\.com|example\\.com)(:' "$RD"
check "joker + nom nu : aucune ServerAlias du nom nu (c'est le ServerName)" test "$(grep -c 'ServerAlias' "$C")" = 1
run install --domain jeedom.example.com --alias '*.*.example.com' --fullchain "$CERT" --key "$KEY"
check "alias *.*.x : code 2" test "$RC" = 2
run install --domain jeedom.example.com --alias 'a*.example.com' --fullchain "$CERT" --key "$KEY"
check "alias a*.x : code 2" test "$RC" = 2
run install --domain jeedom.example.com --alias 'www.example.com' --fullchain "$CERT" --key "$KEY" --alias
check "--alias sans valeur : code 2" test "$RC" = 2

# ---------------------------------------------------------------------------
title "vhost TLS : X-Forwarded-Proto, mod_headers ; redirection derrière un proxy"
check "RequestHeader set X-Forwarded-Proto https dans <IfModule mod_headers.c>" test "$(sed -n '/<IfModule mod_headers.c>/{n;p;}' "$C" | tr -d ' ')" = 'RequestHeadersetX-Forwarded-Proto"https"'
check "a2enmod headers appelé à la 1re installation" called '^a2enmod -q headers$'
check "redirection : X-Forwarded-Ssl: on respecté" grep -q -F "req('X-Forwarded-Ssl') !~ m#^on\$#i" "$RD"
check "redirection : Forwarded proto=https respecté" grep -q "req('Forwarded') !~ m#proto=.?https#i" "$RD"
check "redirection : X-Forwarded-Proto https (casse indifférente)" grep -q "req('X-Forwarded-Proto') !~ m#^https#i" "$RD"

# ---------------------------------------------------------------------------
title "SUSE : /etc/sysconfig/apache2 sauvegardé et restauré"
new_root suse suse apache
mkdir -p "$ROOT/etc/sysconfig" "$ROOT/usr/lib64/apache2"; : > "$ROOT/usr/lib64/apache2/mod_ssl.so"
printf 'APACHE_MODULES="alias"\nAPACHE_SERVER_FLAGS=""\n' > "$ROOT/etc/sysconfig/apache2"
cp "$ROOT/etc/sysconfig/apache2" "$BASE/sysconfig.orig"
FAKE_TEST=fail_pattern FAKE_PATTERN=jeedom-acme-ssl_error run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "échec du test : code 6" test "$RC" = 6
check "a2enmod ssl et a2enflag SSL appelés" test -n "$(grep '^a2enmod ssl' "$ROOT/calls.log")" -a -n "$(grep '^a2enflag SSL' "$ROOT/calls.log")"
check "sysconfig/apache2 restauré à l'identique" cmp "$BASE/sysconfig.orig" "$ROOT/etc/sysconfig/apache2"
run install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY"
check "réussite : code 0, ssl et headers dans APACHE_MODULES, flag SSL" test "$RC" = 0 -a -n "$(grep 'APACHE_MODULES="alias ssl headers"' "$ROOT/etc/sysconfig/apache2")" -a -n "$(grep 'APACHE_SERVER_FLAGS=" SSL"' "$ROOT/etc/sysconfig/apache2")"

# ---------------------------------------------------------------------------
title "ACME_DRYRUN : rien n'est écrit"
new_root dry debian apache
OUT=$(env ACME_ROOT="$ROOT" ACME_DRYRUN=1 PATH="$ROOT/fakebin:$PATH" sh "$SCRIPT" install --domain jeedom.example.com --fullchain "$CERT" --key "$KEY" --redirect 1 2>"$BASE/stderr"); RC=$?
check "code 0, dryrun=1" test "$RC:$(val dryrun)" = "0:1"
check "aucun fichier, aucun appel de faux binaire modifiant" test ! -e "$ROOT/etc/ssl/jeedom-acme" -a -z "$(grep -v -e '^apache2ctl -v' "$ROOT/calls.log")"
check "contenu simulé affiché sur stderr" grep -q 'SSLCertificateFile' "$BASE/stderr"

# ---------------------------------------------------------------------------
title "acmeInstaller (PHP)"
if command -v php >/dev/null 2>&1; then
    new_root php debian apache
    PHPOUT=$(env ACME_TEST_ROOT="$ROOT" ACME_TEST_CERT="$CERT" ACME_TEST_KEY="$KEY" ACME_TEST_OTHER="$BASE/other.pem" \
        ACME_TEST_SANCERT="$BASE/cert3.pem" ACME_TEST_SANKEY="$BASE/key3.pem" \
        PATH="$ROOT/fakebin:$PATH" php "$HERE/test_installer.php" 2>&1); PRC=$?
    printf '%s\n' "$PHPOUT" | sed 's/^/  /'
    P=$(printf '%s\n' "$PHPOUT" | grep -c '^ok ')
    F=$(printf '%s\n' "$PHPOUT" | grep -c '^ÉCHEC ')
    PASS=$((PASS + P)); FAIL=$((FAIL + F))
    [ "$PRC" = 0 ] || { [ "$F" -gt 0 ] || FAIL=$((FAIL + 1)); }
else
    echo "  (php absent : ignoré)"
fi

printf '\n%s réussis, %s échoués\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]

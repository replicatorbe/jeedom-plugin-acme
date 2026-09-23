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

/* ================================================================== OUTILS */

var ACME_AJAX_URL = 'plugins/acme/core/ajax/acme.ajax.php'

/* Intervalle de sondage de la tâche de fond, tant qu'elle tourne. */
var ACME_POLL_MS = 2000

/* Jeton du sondage en cours : chaque nouvel affichage d'équipement en crée un
   nouveau, et une boucle dont le jeton n'est plus le bon s'arrête d'elle-même.
   Jamais deux boucles en parallèle, même après plusieurs clics. Le coeur
   recharge ce script à chaque affichage de la page : le compteur est repris
   s'il existe déjà, sinon une ancienne boucle retrouverait un jeton valide. */
var acmePollToken = (typeof acmePollToken === 'number') ? acmePollToken : 0

/* Sur une erreur de sondage (serveur qui redémarre, réseau coupé), nouvel
   essai après ACME_POLL_RETRY_MS ; abandon après ACME_POLL_MAX_FAILURES échecs
   consécutifs. */
var ACME_POLL_RETRY_MS = 5000
var ACME_POLL_MAX_FAILURES = 10
var acmePollFailures = 0

/* Dernier état connu, pour activer ou non les boutons : tâche en cours, et
   certificat présent (installer ou télécharger n'a de sens qu'avec lui). */
var acmeJobRunning = false
var acmeCertExists = false

function acmeEl(_id) {
  return document.getElementById(_id)
}

function acmeText(_value) {
  return (_value === null || _value === undefined) ? '' : String(_value)
}

function acmeCurrentId() {
  var input = document.querySelector('.eqLogicAttr[data-l1key="id"]')
  return (input === null) ? '' : input.value
}

function acmeAlert(_message, _level) {
  jeedomUtils.showAlert({ message: acmeText(_message), level: _level || 'danger' })
}

/*
   Appel à l'ajax du plugin.

   fetch direct, et non domUtils.ajax : l'ajax exige l'en-tête X-Requested-With
   (protection contre les requêtes forgées), que domUtils.ajax ne pose pas. Et
   domUtils.ajax rejoue la requête sur une erreur 500 : pas souhaitable pour une
   action qui lance une émission.

   ajax::error() du coeur répond en HTTP 200 avec { state: 'error' } : c'est ce
   champ qui fait foi, pas le statut HTTP.
*/
function acmeAjax(_action, _data, _success, _failure) {
  var body = new URLSearchParams()
  body.append('action', _action)
  for (var key in _data) {
    if (Object.prototype.hasOwnProperty.call(_data, key)) {
      body.append(key, _data[key])
    }
  }
  var fail = function (_message) {
    if (typeof _failure === 'function') {
      _failure(_message)
    } else {
      acmeAlert(_message, 'danger')
    }
  }
  fetch(ACME_AJAX_URL, {
    method: 'POST',
    body: body,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'X-Requested-With': 'XMLHttpRequest' }
  }).then(function (response) {
    return response.text().then(function (text) {
      var data = null
      try { data = JSON.parse(text) } catch (e) { }
      if (data === null || typeof data !== 'object') {
        throw new Error('{{Réponse inattendue du serveur}} (HTTP ' + response.status + ')')
      }
      return data
    })
  }).then(function (data) {
    if (data.state !== 'ok') {
      fail(acmeText(data.result) || '{{Erreur inconnue}}')
      return
    }
    _success(data.result)
  }).catch(function (error) {
    fail((error && error.message) ? error.message : '{{Serveur Jeedom injoignable.}}')
  })
}

/* Une ligne de tableau clé / valeur, construite en DOM : insertAdjacentHTML sur
   une table génère un <tbody> par insertion. */
function acmeRow(_label, _value, _className) {
  var tr = document.createElement('tr')
  var th = document.createElement('td')
  th.textContent = _label
  var td = document.createElement('td')
  if (_value instanceof Node) {
    td.appendChild(_value)
  } else {
    td.textContent = acmeText(_value)
  }
  if (_className) { td.className = _className }
  tr.appendChild(th)
  tr.appendChild(td)
  return tr
}

function acmeLabel(_text, _level) {
  var span = document.createElement('span')
  span.className = 'label label-' + _level
  span.textContent = _text
  return span
}

/* ============================================================ FORMULAIRE */

/* Montre les champs propres à l'autorité, à la méthode de validation et au
   fournisseur DNS choisis. */
function acmeToggleFields() {
  var ca = acmeEl('sel_acmeCa')
  var challenge = acmeEl('sel_acmeChallenge')
  var provider = acmeEl('sel_acmeDnsProvider')
  var caValue = ca ? ca.value : 'letsencrypt'
  document.querySelectorAll('.acmeCa').forEach(function (_el) {
    _el.style.display = _el.classList.contains('acmeCa-' + caValue) ? '' : 'none'
  })
  var challengeValue = challenge ? challenge.value : 'dns-01'
  document.querySelectorAll('.acmeChallenge').forEach(function (_el) {
    _el.style.display = _el.classList.contains('acmeChallenge-' + challengeValue) ? '' : 'none'
  })
  var providerValue = provider ? provider.value : ''
  document.querySelectorAll('.acmeDnsProvider').forEach(function (_el) {
    _el.style.display = (_el.getAttribute('data-provider') === providerValue) ? '' : 'none'
  })
  acmeUpdateOvhLink()
}

/* Lien « Créer un jeton OVH » : l'URL dépend du point d'accès choisi. Elles
   sont calculées côté serveur (acmeDnsOvh::createTokenUrl) et transmises par
   sendVarToJS. */
function acmeUpdateOvhLink() {
  var link = acmeEl('a_acmeOvhToken')
  if (link === null) { return }
  var endpoint = document.querySelector('.acmeDnsInput[data-field="endpoint"]')
  var urls = (typeof acmeOvhTokenUrls === 'object' && acmeOvhTokenUrls !== null) ? acmeOvhTokenUrls : {}
  var value = endpoint ? endpoint.value : ''
  if (value === '' && endpoint) { value = endpoint.getAttribute('data-default') || '' }
  if (urls[value]) {
    link.setAttribute('href', urls[value])
    link.style.display = ''
  } else {
    link.setAttribute('href', '#')
    link.style.display = 'none'
  }
}

/* Valeurs par défaut des listes et champs encore vides (équipement neuf) : le
   coeur vide tous les champs avant de charger l'équipement. */
function acmeApplyDefaults() {
  document.querySelectorAll('.eqLogic [data-default]').forEach(function (_el) {
    var def = _el.getAttribute('data-default')
    if (def !== null && def !== '' && (_el.value === '' || _el.value === null)) {
      _el.value = def
    }
  })
}

/* ================================================================== ÉTAT */

var ACME_STATUS = {
  none: ['{{Aucun certificat}}', 'default'],
  valid: ['{{Valide}}', 'success'],
  renew_soon: ['{{À renouveler}}', 'warning'],
  expired: ['{{Expiré}}', 'danger'],
  error: ['{{Émission en échec}}', 'danger']
}

function acmeRenderCert(_cert, _test) {
  var target = acmeEl('div_acmeCert')
  if (target === null) { return }
  target.textContent = ''
  var status = ACME_STATUS[_cert.status] || [acmeText(_cert.status), 'default']
  var table = document.createElement('table')
  table.className = 'table table-condensed acme-certtable'
  table.appendChild(acmeRow('{{Statut}}', acmeLabel(status[0], status[1])))
  if (_cert.exists) {
    table.appendChild(acmeRow('{{Domaines}}', (_cert.domains || []).join(', ')))
    table.appendChild(acmeRow('{{Émetteur}}', _cert.issuer))
    table.appendChild(acmeRow('{{Expiration}}', _cert.expiration))
    var days = parseInt(_cert.daysLeft, 10)
    table.appendChild(acmeRow('{{Jours restants}}', acmeLabel(acmeText(_cert.daysLeft) + ' {{j}}',
      days < 0 ? 'danger' : (days <= 14 ? 'warning' : 'success'))))
    table.appendChild(acmeRow('{{Renouvellement prévu}}', _cert.renewalDue
      ? '{{dès maintenant}} (' + acmeText(_cert.renewalReason) + ')'
      : acmeText(_cert.renewalDate)))
  }
  if (_cert.last_renewal) { table.appendChild(acmeRow('{{Dernier renouvellement}}', _cert.last_renewal)) }
  /* installed : le serveur web sert ce certificat-ci ; installed_outdated :
     il sert un certificat plus ancien de cet équipement. */
  if (_cert.installed) {
    var served = document.createElement('span')
    served.appendChild(acmeLabel('{{Oui, ce certificat}}', 'success'))
    if (_cert.installed_at) { served.appendChild(document.createTextNode(' ' + acmeText(_cert.installed_at))) }
    table.appendChild(acmeRow('{{Installé dans le serveur web}}', served))
  } else if (_cert.installed_outdated) {
    table.appendChild(acmeRow('{{Installé dans le serveur web}}',
      acmeLabel('{{Ancien certificat : réinstallation à faire}}', 'warning')))
  } else if (_cert.installed_at) {
    table.appendChild(acmeRow('{{Installé dans le serveur web}}', _cert.installed_at))
  }
  /* L'émission et l'installation échouent séparément : un certificat obtenu
     mais refusé par le serveur web n'est pas un renouvellement en échec. */
  if (_cert.last_error) {
    var err = acmeRow('{{Dernière émission en échec}}', _cert.last_error)
    err.querySelector('td:last-child').style.color = 'var(--al-danger-color)'
    table.appendChild(err)
  }
  if (_cert.install_error) {
    var installErr = acmeRow('{{Installation dans le serveur web en échec}}', _cert.install_error)
    installErr.querySelector('td:last-child').style.color = 'var(--al-danger-color)'
    table.appendChild(installErr)
  }
  target.appendChild(table)
  acmeCertExists = !!_cert.exists
  acmeUpdateButtons()

  var testTarget = acmeEl('div_acmeTest')
  if (testTarget === null) { return }
  testTarget.textContent = ''
  if (_test && _test.exists) {
    var info = document.createElement('div')
    info.className = 'alert alert-info'
    info.style.marginBottom = '0'
    info.textContent = '{{Dernier essai sur le staging réussi}} : ' + (_test.domains || []).join(', ')
      + ' — ' + acmeText(_test.issuer) + ' — {{valable jusqu\'au}} ' + acmeText(_test.expiration)
      + '. {{Ce certificat de test n\'est reconnu par aucun navigateur et n\'est jamais installé.}}'
    testTarget.appendChild(info)
  }
}

var ACME_JOB_LABELS = {
  issue: '{{Émission}}',
  renew: '{{Renouvellement}}',
  staging: '{{Essai sur le staging}}',
  install: '{{Installation dans le serveur web}}',
  uninstall: '{{Désinstallation du serveur web}}'
}

function acmeRenderJob(_job) {
  var target = acmeEl('div_acmeJobState')
  var log = acmeEl('pre_acmeJobLog')
  if (target === null || log === null) { return }
  target.textContent = ''
  var state = acmeText(_job.state) || 'idle'
  var what = ACME_JOB_LABELS[_job.action] || acmeText(_job.action)
  if (state === 'idle') {
    target.appendChild(acmeLabel('{{Aucune tâche}}', 'default'))
  } else if (_job.running) {
    target.appendChild(acmeLabel(what + ' {{en cours}}', 'info'))
    var step = document.createElement('span')
    step.style.marginLeft = '8px'
    step.innerHTML = '<i class="fas fa-spinner fa-spin"></i> '
    step.appendChild(document.createTextNode(acmeText(_job.step)))
    target.appendChild(step)
  } else {
    var ok = (state === 'success')
    target.appendChild(acmeLabel(what + ' : ' + (ok ? '{{terminé}}' : '{{échec}}'), ok ? 'success' : 'danger'))
    if (_job.finished) {
      var when = document.createElement('span')
      when.style.marginLeft = '8px'
      when.textContent = new Date(_job.finished * 1000).toLocaleString()
      target.appendChild(when)
    }
    if (_job.result) {
      var result = document.createElement('div')
      result.style.marginTop = '6px'
      result.textContent = acmeText(_job.result)
      target.appendChild(result)
    }
  }
  var lines = Array.isArray(_job.lines) ? _job.lines : []
  log.textContent = ''
  lines.forEach(function (_line) {
    var div = document.createElement('div')
    div.textContent = acmeText(_line.t) + '  ' + acmeText(_line.m)
    if (_line.l === 'warning' || _line.l === 'error') { div.className = 'acme-' + _line.l }
    log.appendChild(div)
  })
  log.style.display = lines.length > 0 ? '' : 'none'
  log.scrollTop = log.scrollHeight
  acmeJobRunning = !!_job.running
  acmeUpdateButtons()
}

/* Boutons inactifs pendant une tâche ; installation et téléchargements
   inactifs tant qu'aucun certificat n'existe. */
function acmeUpdateButtons() {
  document.querySelectorAll('.acmeAction').forEach(function (_btn) {
    var needsCert = (_btn.getAttribute('data-job') === 'install')
    _btn.classList.toggle('disabled', acmeJobRunning || (needsCert && !acmeCertExists))
    _btn.setAttribute('title', (needsCert && !acmeCertExists) ? '{{Aucun certificat : obtenez-le d\'abord.}}' : '')
  })
  document.querySelectorAll('.acmeDownload').forEach(function (_btn) {
    _btn.classList.toggle('disabled', !acmeCertExists)
    _btn.setAttribute('title', acmeCertExists ? '' : '{{Aucun certificat : obtenez-le d\'abord.}}')
  })
}

/* Avertissement de sondage, sous l'état de la tâche ; l'état du certificat
   affiché reste en place. */
function acmePollWarning(_message) {
  var target = acmeEl('div_acmeJobState')
  if (target === null) { return }
  var div = acmeEl('div_acmePollWarning')
  if (div === null) {
    div = document.createElement('div')
    div.id = 'div_acmePollWarning'
    div.style.marginTop = '6px'
    target.appendChild(div)
  }
  if (_message === '') {
    div.remove()
    return
  }
  div.className = 'alert alert-warning'
  div.style.marginBottom = '0'
  div.textContent = _message
}

/* Sonde l'état toutes les 2 s tant qu'une tâche tourne ; une seule fois sinon.
   La boucle s'arrête si l'on change d'équipement ou de page. */
function acmePoll(_id, _token) {
  if (_token !== acmePollToken || acmeEl('div_acmeJobState') === null || acmeCurrentId() !== _id) {
    return
  }
  acmeAjax('jobStatus', { id: _id }, function (result) {
    if (_token !== acmePollToken || acmeCurrentId() !== _id) { return }
    acmePollFailures = 0
    acmeRenderJob(result.job || {})
    acmeRenderCert(result.cert || {}, result.test || {})
    if (result.job && result.job.running) {
      setTimeout(function () { acmePoll(_id, _token) }, ACME_POLL_MS)
    }
  }, function (_message) {
    if (_token !== acmePollToken || acmeCurrentId() !== _id) { return }
    acmePollFailures++
    if (acmePollFailures >= ACME_POLL_MAX_FAILURES) {
      /* Abandon : les boutons redeviennent utilisables, la tâche de fond,
         elle, continue peut-être ; rouvrir l'équipement relance le suivi. */
      acmeJobRunning = false
      acmeUpdateButtons()
      acmePollWarning('{{Suivi de la tâche abandonné après plusieurs échecs}} : ' + acmeText(_message)
        + ' {{Rouvrez l\'équipement pour relancer le suivi.}}')
      return
    }
    acmePollWarning('{{Impossible de lire l\'état de la tâche}} (' + acmePollFailures + '/' + ACME_POLL_MAX_FAILURES + ') : '
      + acmeText(_message) + ' {{Nouvel essai dans 5 s.}}')
    setTimeout(function () { acmePoll(_id, _token) }, ACME_POLL_RETRY_MS)
  })
}

function acmeStartPolling() {
  var id = acmeCurrentId()
  acmePollToken++
  acmePollFailures = 0
  if (id === '') { return }
  acmePoll(id, acmePollToken)
}

/* ================================================================ ACTIONS */

var ACME_CONFIRM = {
  renew: '{{Émettre un nouveau certificat maintenant, même si l\'actuel est encore valide ? Let\'s Encrypt limite le nombre de certificats identiques par semaine.}}',
  install: '{{Configurer le serveur web de Jeedom en HTTPS avec ce certificat ? La configuration existante est sauvegardée et restaurée si le test échoue.}}',
  uninstall: '{{Retirer la configuration HTTPS ajoutée par le plugin ? Le serveur web n\'a qu\'une configuration HTTPS : c\'est tout le HTTPS de Jeedom qui disparaît, quel que soit le certificat. Une page ouverte en https:// (celle-ci comprise) ne répondra plus ; vérifiez que vous avez un accès en http:// par l\'adresse IP locale avant de continuer.}}'
}

function acmeLaunch(_job) {
  var id = acmeCurrentId()
  if (id === '') {
    acmeAlert('{{Enregistrez l\'équipement avant cette action.}}', 'warning')
    return
  }
  if (jeeFrontEnd.modifyWithoutSave) {
    acmeAlert('{{Des modifications ne sont pas enregistrées : sauvegardez d\'abord, les actions utilisent la configuration enregistrée.}}', 'warning')
    return
  }
  var go = function () {
    acmeAjax('launch', { id: id, job: _job }, function (job) {
      acmeRenderJob(job)
      acmeStartPolling()
    })
  }
  if (ACME_CONFIRM[_job]) {
    jeeDialog.confirm(ACME_CONFIRM[_job], function (result) {
      if (result) { go() }
    })
    return
  }
  go()
}

function acmeDownload(_file) {
  var id = acmeCurrentId()
  if (id === '') { return }
  acmeAjax('download', { id: id, file: _file }, function (result) {
    var blob = new Blob([acmeText(result.content)], { type: 'application/x-pem-file' })
    var url = URL.createObjectURL(blob)
    var a = document.createElement('a')
    a.href = url
    a.download = acmeText(result.filename) || (_file + '.pem')
    /* noOnePageLoad : le coeur intercepte les clics sur les liens de la page. */
    a.className = 'noOnePageLoad'
    a.style.display = 'none'
    document.body.appendChild(a)
    a.click()
    setTimeout(function () {
      URL.revokeObjectURL(url)
      a.remove()
    }, 1000)
  })
}

function acmeTestDns() {
  var provider = acmeEl('sel_acmeDnsProvider')
  var target = acmeEl('div_acmeTestDns')
  if (provider === null || target === null) { return }
  var config = {}
  var container = document.querySelector('.acmeDnsProvider[data-provider="' + provider.value + '"]')
  if (container !== null) {
    container.querySelectorAll('.acmeDnsInput').forEach(function (_input) {
      config[_input.getAttribute('data-field')] = _input.value
    })
  }
  target.style.display = ''
  /* Le résumé du fournisseur tient sur plusieurs lignes. */
  target.style.whiteSpace = 'pre-line'
  target.className = 'alert alert-info'
  target.textContent = '{{Test en cours…}}'
  acmeAjax('testDns', { id: acmeCurrentId(), provider: provider.value, config: JSON.stringify(config) }, function (result) {
    target.className = 'alert alert-success'
    target.textContent = acmeText(result.summary)
  }, function (_message) {
    target.className = 'alert alert-danger'
    target.textContent = _message
  })
}

/* ========================================================= NOTIFICATIONS */

/*
   Actions de notification : même modèle qu'un bloc action de scénario. Chaque
   ligne porte une commande (ou un bloc : scénario, variable…), ses options
   rendues par le coeur, et les événements qui la déclenchent. Les champs sont
   des expressionAttr, jamais des eqLogicAttr : c'est saveEqLogic() qui relève
   la liste et la range dans configuration.notify_actions.
*/

function acmeNotifyAddRow(_action) {
  var container = acmeEl('div_acmeNotify')
  if (container === null) { return null }
  var action = _action || {}
  if (!isset(action.options) || action.options === null) { action.options = {} }
  if (!isset(action.events) || action.events === null || typeof action.events !== 'object') {
    action.events = Object.assign({}, acmeNotifyDefaults)
  }

  var optionsId = jeedomUtils.uniqId()
  var html = '<div class="acmeNotifyAction expression" style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid rgba(var(--txt-color),.1);">'
  html += '<input class="expressionAttr" data-l1key="cmd_id" style="display:none;">'
  html += '<div class="form-group" style="margin:0;">'
  html += '<div class="col-sm-5">'
  html += '<div class="input-group">'
  html += '<span class="input-group-btn">'
  html += '<a class="btn btn-default btn-sm acmeNotifyRemove roundedLeft" title="{{Retirer cette action}}"><i class="fas fa-minus-circle"></i></a>'
  html += '</span>'
  html += '<input class="expressionAttr form-control input-sm acmeNotifyCmd" data-l1key="cmd" placeholder="{{Commande à exécuter (mail, Telegram…)}}">'
  html += '<span class="input-group-btn">'
  html += '<a class="btn btn-default btn-sm acmeNotifyPickBlock" title="{{Choisir un bloc (scénario, variable…)}}"><i class="fas fa-tasks"></i></a>'
  html += '<a class="btn btn-default btn-sm acmeNotifyPickCmd roundedRight" title="{{Choisir une commande}}"><i class="fas fa-list-alt"></i></a>'
  html += '</span>'
  html += '</div>'
  html += '<div style="margin-top:6px;">'
  for (var event in acmeNotifyEvents) {
    if (!Object.prototype.hasOwnProperty.call(acmeNotifyEvents, event)) { continue }
    html += '<label class="checkbox-inline" style="margin-right:10px;">'
    html += '<input type="checkbox" class="expressionAttr" data-l1key="events" data-l2key="' + event + '"> ' + acmeNotifyEvents[event]
    html += '</label>'
  }
  html += '</div>'
  html += '</div>'
  html += '<div class="col-sm-7 actionOptions" id="' + optionsId + '"></div>'
  html += '</div>'
  html += '</div>'

  var wrapper = document.createElement('div')
  /* html() et non innerHTML : même chemin que le coeur pour ses blocs. */
  wrapper.html(html)
  wrapper.setJeeValues(action, '.expressionAttr')
  /* setJeeValues ne décoche pas une case absente : on pose chaque case. */
  wrapper.querySelectorAll('.expressionAttr[data-l1key="events"]').forEach(function (_box) {
    var key = _box.getAttribute('data-l2key')
    _box.checked = (action.events[key] == 1 || action.events[key] === true || action.events[key] === '1')
  })
  var row = wrapper.firstElementChild
  container.appendChild(row)
  /* Les options connues restent attachées à la ligne tant que le coeur ne les a
     pas redessinées : un enregistrement fait avant sa réponse n'écrit pas du
     vide à la place d'un message rédigé. */
  row.acmePendingOptions = action.options
  return row
}

/* Redessine les options des lignes dont la commande a changé (toutes si
   _force), en un seul aller-retour vers le coeur. Les options connues sont
   toujours conservées si le rendu échoue. */
function acmeNotifyRefreshOptions(_force) {
  var rows = document.querySelectorAll('#div_acmeNotify .acmeNotifyAction')
  var params = []
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i]
    var input = row.querySelector('.acmeNotifyCmd')
    var target = row.querySelector('.actionOptions')
    if (input === null || target === null) { continue }
    var expression = acmeText(input.value).trim()
    if (_force !== true && input.getAttribute('prevalue') === expression) { continue }
    input.setAttribute('prevalue', expression)

    var current = row.getJeeValues('.expressionAttr')[0]
    var options = (isset(current) && isset(current.options) && current.options !== null) ? current.options : {}
    if (isset(row.acmePendingOptions) && row.acmePendingOptions !== null) {
      options = Object.assign({}, row.acmePendingOptions, options)
    }
    row.acmePendingOptions = options
    if (expression === '') {
      target.innerHTML = ''
      row.acmePendingOptions = null
      continue
    }
    params.push({ expression: expression, options: options, id: target.id })
  }
  if (params.length === 0) { return }
  jeedom.cmd.displayActionsOption({
    params: params,
    error: function (error) {
      acmeAlert('{{Les options des actions n\'ont pas pu être affichées. Ce qui est enregistré est conservé.}} ' + acmeText(error.message), 'warning')
    },
    success: function (data) {
      var list = Array.isArray(data) ? data : []
      for (var j = 0; j < list.length; j++) {
        var target = acmeEl(list[j].id)
        if (target === null) { continue }
        var content = list[j].html
        if (content !== null && typeof content === 'object' && isset(content.html)) { content = content.html }
        content = acmeText(content)
        if (content === '') { continue }
        target.html(content)
        var row = target.closest('.acmeNotifyAction')
        if (row !== null) { row.acmePendingOptions = null }
      }
      jeedomUtils.taAutosize()
    }
  })
}

/* Relève les actions de l'écran, avec leurs options (y compris celles que le
   coeur n'a pas encore redessinées). */
function acmeNotifyRead() {
  var actions = []
  document.querySelectorAll('#div_acmeNotify .acmeNotifyAction').forEach(function (_row) {
    var action = _row.getJeeValues('.expressionAttr')[0]
    if (!isset(action) || acmeText(action.cmd).trim() === '') { return }
    if (!isset(action.options) || action.options === null) { action.options = {} }
    if (isset(_row.acmePendingOptions) && _row.acmePendingOptions !== null) {
      action.options = Object.assign({}, _row.acmePendingOptions, action.options)
    }
    var events = {}
    _row.querySelectorAll('.expressionAttr[data-l1key="events"]').forEach(function (_box) {
      events[_box.getAttribute('data-l2key')] = _box.checked ? 1 : 0
    })
    actions.push({ cmd: acmeText(action.cmd).trim(), cmd_id: acmeText(action.cmd_id), options: action.options, events: events })
  })
  return actions
}

function acmeNotifyPrint(_eqLogic) {
  var container = acmeEl('div_acmeNotify')
  if (container === null) { return }
  container.innerHTML = ''
  var result = acmeEl('div_acmeNotifyResult')
  if (result !== null) { result.innerHTML = '' }
  var actions = (_eqLogic && _eqLogic.configuration) ? _eqLogic.configuration.notify_actions : []
  if (typeof actions === 'string') {
    try { actions = JSON.parse(actions) } catch (e) { actions = [] }
  }
  if (!Array.isArray(actions)) { actions = [] }
  actions.forEach(function (_action) { acmeNotifyAddRow(_action) })
  acmeNotifyRefreshOptions(true)
}

function acmeNotifyTest() {
  var target = acmeEl('div_acmeNotifyResult')
  if (target === null) { return }
  if (acmeCurrentId() === '') {
    acmeAlert('{{Sauvegardez d\'abord l\'équipement.}}', 'warning')
    return
  }
  if (jeeFrontEnd.modifyWithoutSave) {
    acmeAlert('{{Des modifications ne sont pas sauvegardées : l\'essai utilise les actions enregistrées. Sauvegardez d\'abord.}}', 'warning')
  }
  target.className = 'alert alert-info'
  target.textContent = '{{Envoi en cours…}}'
  acmeAjax('testNotify', { id: acmeCurrentId() }, function (result) {
    var report = Array.isArray(result.report) ? result.report : []
    var allOk = report.length > 0
    target.innerHTML = ''
    report.forEach(function (_line) {
      if (!_line.ok) { allOk = false }
      var div = document.createElement('div')
      div.textContent = (_line.ok ? '✔ ' : '✘ ') + acmeText(_line.cmd) + ' : ' + acmeText(_line.result)
      target.appendChild(div)
    })
    target.className = allOk ? 'alert alert-success' : 'alert alert-warning'
  }, function (_message) {
    target.className = 'alert alert-danger'
    target.textContent = _message
  })
}

/* ======================================================= HOOKS DU COEUR */

/* Appelé par plugin.template.js une fois l'équipement chargé dans la page. */
function printEqLogic(_eqLogic) {
  /* jeeValue('') ne décoche pas une case : sans cela, une case cochée sur
     l'équipement précédent le resterait sur celui-ci si la clé n'y existe pas
     (équipement neuf, ou jamais enregistré avec cette option). */
  var configuration = (_eqLogic && _eqLogic.configuration && typeof _eqLogic.configuration === 'object') ? _eqLogic.configuration : {}
  document.querySelectorAll('.eqLogic input[type="checkbox"].eqLogicAttr[data-l1key="configuration"]').forEach(function (_box) {
    var key = _box.getAttribute('data-l2key')
    if (!Object.prototype.hasOwnProperty.call(configuration, key) || acmeText(configuration[key]) === '') {
      _box.checked = false
    }
  })
  acmeJobRunning = false
  acmeCertExists = false
  acmeApplyDefaults()
  acmeToggleFields()
  var testDns = acmeEl('div_acmeTestDns')
  if (testDns !== null) { testDns.style.display = 'none' }
  var cert = acmeEl('div_acmeCert')
  if (cert !== null) { cert.innerHTML = '<div class="alert alert-info">{{Chargement…}}</div>' }
  var test = acmeEl('div_acmeTest')
  if (test !== null) { test.textContent = '' }
  acmeRenderJob({ state: 'idle' })
  acmeNotifyPrint(_eqLogic)
  acmeShowDisabled()
  acmeStartPolling()
}

/* Un équipement désactivé est ignoré par le cron : pas de renouvellement
   automatique, pas d'alerte. Les boutons marchent quand même, ce qui peut
   faire croire que tout est automatique : on le dit. */
function acmeShowDisabled() {
  var box = document.querySelector('.eqLogicAttr[data-l1key="isEnable"]')
  var warning = acmeEl('div_acmeDisabled')
  if (box === null || warning === null) { return }
  warning.style.display = box.checked ? 'none' : ''
}

/* Appelé par plugin.template.js juste avant l'envoi : la liste des actions de
   notification n'est pas faite d'eqLogicAttr, on la range ici. */
function saveEqLogic(_eqLogic) {
  if (!isset(_eqLogic.configuration) || _eqLogic.configuration === null) { _eqLogic.configuration = {} }
  _eqLogic.configuration.notify_actions = acmeNotifyRead()
  return _eqLogic
}

function addCmdToTable(_cmd) {
  if (!isset(_cmd)) {
    var _cmd = { configuration: {} }
  }
  if (!isset(_cmd.configuration)) {
    _cmd.configuration = {}
  }

  var tr = '<td>'
  /* Sans ce champ, chaque enregistrement détruit puis recrée les commandes :
     l'historique est perdu et les scénarios pointent dans le vide. */
  tr += '<span class="cmdAttr" data-l1key="id" style="display:none;"></span>'
  tr += '<div class="input-group">'
  tr += '<input class="cmdAttr form-control input-sm roundedLeft" data-l1key="name" placeholder="{{Nom}}">'
  tr += '<span class="input-group-btn">'
  tr += '<a class="cmdAction btn btn-sm btn-default" data-l1key="chooseIcon" title="{{Choisir une icône}}"><i class="fas fa-icons"></i></a>'
  tr += '</span>'
  tr += '<span class="cmdAttr input-group-addon roundedRight" data-l1key="display" data-l2key="icon" style="font-size:19px;padding:0 5px 0 0!important;"></span>'
  tr += '</div>'
  tr += '</td>'
  tr += '<td>'
  tr += '<span class="type" type="' + init(_cmd.type) + '">' + jeedom.cmd.availableType() + '</span>'
  tr += '<span class="subType" subType="' + init(_cmd.subType) + '"></span>'
  tr += '</td>'
  tr += '<td>'
  tr += '<label class="checkbox-inline"><input type="checkbox" class="cmdAttr" data-l1key="isVisible" checked>{{Afficher}}</label>'
  if (init(_cmd.type) === 'info') {
    tr += '<label class="checkbox-inline"><input type="checkbox" class="cmdAttr" data-l1key="isHistorized">{{Historiser}}</label>'
  }
  tr += '<span class="cmdAttr" data-l1key="htmlstate" style="display:inline-block;margin-left:5px;"></span>'
  tr += '</td>'
  tr += '<td>'
  if (is_numeric(_cmd.id)) {
    tr += '<a class="btn btn-default btn-xs cmdAction" data-action="configure"><i class="fas fa-cogs"></i></a> '
    tr += '<a class="btn btn-default btn-xs cmdAction" data-action="test"><i class="fas fa-rss"></i> {{Tester}}</a> '
  }
  tr += '</td>'

  var newRow = document.createElement('tr')
  newRow.innerHTML = tr
  newRow.classList.add('cmd')
  newRow.setAttribute('data-cmd_id', init(_cmd.id))
  newRow.setAttribute('title', '{{Identifiant interne}} : ' + init(_cmd.logicalId))
  document.getElementById('table_cmd').querySelector('tbody').appendChild(newRow)
  newRow.setJeeValues(_cmd, '.cmdAttr')
  /* L'ordre compte : changeType après setJeeValues, jamais l'inverse. */
  jeedom.cmd.changeType(newRow, init(_cmd.subType))
}

/* ============================================================== ÉCOUTEURS */

/* Les pages de plugin sont chargées en ajax : DOMContentLoaded a déjà eu lieu
   quand ce script s'exécute. Les écouteurs sont posés par délégation sur le
   conteneur de page, que le coeur remplace (écouteurs compris) à chaque
   changement de page : pas de doublon au rechargement. */
var acmeContainer = document.getElementById('div_pageContainer') || document.body

acmeContainer.addEventListener('click', function (_event) {
  var target = _event.target
  if (target === null || typeof target.closest !== 'function') { return }

  var action = target.closest('.acmeAction')
  if (action !== null) {
    _event.preventDefault()
    if (!action.classList.contains('disabled')) {
      acmeLaunch(action.getAttribute('data-job'))
    }
    return
  }
  var download = target.closest('.acmeDownload')
  if (download !== null) {
    _event.preventDefault()
    if (!download.classList.contains('disabled')) {
      acmeDownload(download.getAttribute('data-file'))
    }
    return
  }
  if (target.closest('#bt_acmeTestDns') !== null) {
    _event.preventDefault()
    acmeTestDns()
    return
  }
  if (target.closest('#bt_acmeAddNotify') !== null) {
    _event.preventDefault()
    acmeNotifyAddRow({ cmd: '', cmd_id: '', options: {} })
    jeeFrontEnd.modifyWithoutSave = true
    return
  }
  if (target.closest('#bt_acmeTestNotify') !== null) {
    _event.preventDefault()
    acmeNotifyTest()
    return
  }
  var notifyRemove = target.closest('.acmeNotifyRemove')
  if (notifyRemove !== null) {
    _event.preventDefault()
    notifyRemove.closest('.acmeNotifyAction').remove()
    jeeFrontEnd.modifyWithoutSave = true
    return
  }
  var pickCmd = target.closest('.acmeNotifyPickCmd')
  if (pickCmd !== null) {
    _event.preventDefault()
    var cmdRow = pickCmd.closest('.acmeNotifyAction')
    jeedom.cmd.getSelectModal({ cmd: { type: 'action' } }, function (result) {
      if (!isset(result) || acmeText(result.human).trim() === '') { return }
      cmdRow.querySelector('.expressionAttr[data-l1key="cmd"]').jeeValue(result.human)
      cmdRow.querySelector('.expressionAttr[data-l1key="cmd_id"]').jeeValue((isset(result.cmd) && isset(result.cmd.id)) ? acmeText(result.cmd.id) : '')
      acmeNotifyRefreshOptions(false)
      jeeFrontEnd.modifyWithoutSave = true
    })
    return
  }
  var pickBlock = target.closest('.acmeNotifyPickBlock')
  if (pickBlock !== null) {
    _event.preventDefault()
    var blockRow = pickBlock.closest('.acmeNotifyAction')
    jeedom.getSelectActionModal({}, function (result) {
      if (!isset(result) || acmeText(result.human).trim() === '') { return }
      blockRow.querySelector('.expressionAttr[data-l1key="cmd"]').jeeValue(result.human)
      blockRow.querySelector('.expressionAttr[data-l1key="cmd_id"]').jeeValue('')
      acmeNotifyRefreshOptions(false)
      jeeFrontEnd.modifyWithoutSave = true
    })
    return
  }
  var tokenLink = target.closest('#a_acmeOvhToken')
  if (tokenLink !== null && tokenLink.getAttribute('href') === '#') {
    _event.preventDefault()
  }
})

acmeContainer.addEventListener('change', function (_event) {
  var target = _event.target
  if (target === null || typeof target.matches !== 'function') { return }
  if (target.matches('#sel_acmeCa, #sel_acmeChallenge, #sel_acmeDnsProvider, .acmeDnsInput[data-field="endpoint"]')) {
    acmeToggleFields()
  }
  if (target.matches('.eqLogicAttr[data-l1key="isEnable"]')) {
    acmeShowDisabled()
  }
})

/* Commande saisie ou collée à la main : options redessinées en quittant le
   champ (focusout remonte, contrairement à blur). L'identifiant mémorisé ne
   correspond plus : le serveur le recalcule à l'enregistrement. */
acmeContainer.addEventListener('focusout', function (_event) {
  var target = _event.target
  if (target === null || typeof target.matches !== 'function' || !target.matches('.acmeNotifyCmd')) { return }
  if (target.getAttribute('prevalue') !== acmeText(target.value).trim()) {
    var idField = target.closest('.acmeNotifyAction').querySelector('.expressionAttr[data-l1key="cmd_id"]')
    if (idField !== null) { idField.value = '' }
    acmeNotifyRefreshOptions(false)
  }
})

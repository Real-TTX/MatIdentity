/* MatIdentity: the behaviour only this app has. Plain JavaScript, no build step.
   The shell, the theme, dialogs (data-confirm), forms, validation, copy (data-copy) and the dependent fields (data-show-if) are the toolkit's:
   wwwroot/matui/matui.js. Every behaviour here is switched on by a data-* attribute, so several of the same control can live on one page. */
(function () {
  'use strict';

  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  // ------------------------------------------------------------------ a select that applies at once: <form data-autosubmit> (the role of a person in an app)

  $$('form[data-autosubmit]').forEach(function (form) {
    form.addEventListener('change', function (e) { if (e.target.matches('select')) { form.requestSubmit ? form.requestSubmit() : form.submit(); } });
  });

  // ------------------------------------------------------------------ passkeys (WebAuthn): the server is PasskeyEndpoints.cs

  // WebAuthn works with bytes, the server with Base64url text.
  function toBytes(text) {
    var b64 = text.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) { b64 += '='; }
    var raw = atob(b64), bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) { bytes[i] = raw.charCodeAt(i); }
    return bytes.buffer;
  }
  function toText(buffer) {
    if (!buffer) { return null; }
    var bytes = new Uint8Array(buffer), raw = '';
    for (var i = 0; i < bytes.length; i++) { raw += String.fromCharCode(bytes[i]); }
    return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function antiforgery() {
    var input = document.querySelector('input[name="__RequestVerificationToken"]');
    return input ? input.value : '';
  }
  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'RequestVerificationToken': antiforgery() },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      if (r.status === 204) { return {}; }
      return r.json().catch(function () { return {}; }).then(function (d) { if (!r.ok) { throw new Error(d.error || ('HTTP ' + r.status)); } return d; });
    });
  }
  function showError(root, message) {
    var box = root && root.querySelector('[data-passkey-error]') || document.querySelector('[data-passkey-error]');
    if (!box) { return; }
    box.querySelector('.mat-alert__body').textContent = message;
    box.hidden = false;
  }
  function friendly(err) {
    // The browser's words for "the person cancelled" are long and technical.
    return err && err.name === 'NotAllowedError' ? 'The passkey was not used (cancelled or timed out).' : (err && err.message) || 'Something went wrong.';
  }
  var supported = !!(window.PublicKeyCredential && navigator.credentials);

  // Adding a passkey to the account: <div data-passkey-register> with an input #passkey-name and a [data-passkey-add] button.
  $$('[data-passkey-register]').forEach(function (root) {
    var button = root.querySelector('[data-passkey-add]');
    if (!button) { return; }
    if (!supported) { button.disabled = true; showError(root, 'This browser cannot use passkeys.'); return; }
    button.addEventListener('click', function () {
      button.disabled = true;
      post('/api/passkeys/register/options').then(function (d) {
        var o = d.options;
        o.challenge = toBytes(o.challenge);
        o.user.id = toBytes(o.user.id);
        (o.excludeCredentials || []).forEach(function (c) { c.id = toBytes(c.id); });
        return navigator.credentials.create({ publicKey: o }).then(function (cred) {
          var name = root.querySelector('#passkey-name');
          return post('/api/passkeys/register', {
            id: d.id,
            name: name ? name.value : '',
            response: {
              id: cred.id, rawId: toText(cred.rawId), type: cred.type,
              response: {
                attestationObject: toText(cred.response.attestationObject),
                clientDataJSON: toText(cred.response.clientDataJSON),
                transports: cred.response.getTransports ? cred.response.getTransports() : []
              },
              clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
            }
          });
        });
      }).then(function () { location.reload(); })
        .catch(function (err) { showError(root, friendly(err)); button.disabled = false; });
    });
  });

  // Signing in with a passkey: <button data-passkey-signin="passkey|second-step" data-return-url="...">.
  $$('[data-passkey-signin]').forEach(function (button) {
    if (!supported) { button.hidden = true; return; }
    button.addEventListener('click', function () {
      button.disabled = true;
      post('/api/passkeys/signin/options', { mode: button.getAttribute('data-passkey-signin') }).then(function (d) {
        var o = d.options;
        o.challenge = toBytes(o.challenge);
        (o.allowCredentials || []).forEach(function (c) { c.id = toBytes(c.id); });
        return navigator.credentials.get({ publicKey: o }).then(function (cred) {
          return post('/api/passkeys/signin', {
            id: d.id,
            returnUrl: button.getAttribute('data-return-url') || '/',
            response: {
              id: cred.id, rawId: toText(cred.rawId), type: cred.type,
              response: {
                authenticatorData: toText(cred.response.authenticatorData),
                clientDataJSON: toText(cred.response.clientDataJSON),
                signature: toText(cred.response.signature),
                userHandle: toText(cred.response.userHandle)
              },
              clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
            }
          });
        });
      }).then(function (d) { location.href = d.redirect || '/'; })
        .catch(function (err) { showError(button.parentElement, friendly(err)); button.disabled = false; });
    });
  });
})();

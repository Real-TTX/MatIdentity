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
})();

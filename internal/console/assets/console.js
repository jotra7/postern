// The console's only script. It refreshes the fleet view periodically so an
// operator watching a rollout does not have to reload by hand.
//
// It reloads with a plain navigation rather than fetching and patching the
// DOM, and that is deliberate: a refresh is a GET, a GET performs no action
// in this console, and a navigation carries the same Host and fetch-metadata
// checks every other request does. Nothing here posts, so nothing here
// touches the CSRF token.
(function () {
  "use strict";
  var REFRESH_MS = 30000;

  // Only the fleet view. A host page carries forms with typed-in values, and
  // a refresh under an operator's fingers would discard them.
  if (window.location.pathname !== "/") return;

  var timer = null;
  function schedule() {
    if (timer !== null) return;
    // When the operator has opted into an active liveness sweep, that sweep
    // owns the refresh: it re-measures every host and reloads on the way back,
    // so the plain reload stands down rather than racing it. Unticked — the
    // default — this reads false and the reload behaves exactly as it always
    // has.
    var sweep = document.getElementById("auto-sweep");
    if (sweep && sweep.checked) return;
    timer = window.setTimeout(function () { window.location.reload(); }, REFRESH_MS);
  }
  function cancel() {
    if (timer === null) return;
    window.clearTimeout(timer);
    timer = null;
  }

  // A hidden tab reloading on a timer keeps an unlocked key's idle window
  // from ever being the thing that drops it. Rendering does not touch the
  // window server-side either, but not reloading a tab nobody is looking at
  // is the cheaper half of that.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) { cancel(); } else { schedule(); }
  });
  if (!document.hidden) schedule();
})();

// The opt-in liveness sweep. When the operator ticks "auto refresh", the fleet
// re-measures every host on a timer by submitting the sweep form — a real POST
// navigation, which the content-security policy and the fetch-metadata guard
// both allow where an XHR would be refused. The plain reloader above stands
// down while this is on, so the two never race. The choice is remembered in
// localStorage, because a sweep reloads the page and the box has to come back
// ticked for the next one to fire.
(function () {
  "use strict";
  if (window.location.pathname !== "/") return;

  var box = document.getElementById("auto-sweep");
  var form = document.querySelector('form[action="/status-all"]');
  if (!box || !form) return;

  var KEY = "postern.auto-sweep";
  var SWEEP_MS = 30000;
  var timer = null;

  function stored() {
    try { return window.localStorage.getItem(KEY) === "1"; } catch (e) { return false; }
  }
  function remember(on) {
    try {
      if (on) { window.localStorage.setItem(KEY, "1"); } else { window.localStorage.removeItem(KEY); }
    } catch (e) { /* private mode or a full store: the box still works, it just forgets across reloads */ }
  }
  function cancel() {
    if (timer === null) return;
    window.clearTimeout(timer);
    timer = null;
  }
  function schedule() {
    if (timer !== null || document.hidden) return;
    timer = window.setTimeout(function () { form.requestSubmit(); }, SWEEP_MS);
  }

  box.checked = stored();

  box.addEventListener("change", function () {
    remember(box.checked);
    if (box.checked) { schedule(); } else { cancel(); }
  });

  // A hidden tab does not sweep: a POST on a timer nobody is watching would
  // keep the operator key's idle window from ever being what drops it.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) { cancel(); } else if (box.checked) { schedule(); }
  });

  if (box.checked && !document.hidden) schedule();
})();

(() => {
  "use strict";
  const endpoint = "/_analytics";
  let visibleStartedAt = document.visibilityState === "visible" ? Date.now() : null;
  let visibleMilliseconds = 0;
  const visibleSeconds = () => Math.round((visibleMilliseconds + (visibleStartedAt ? Date.now() - visibleStartedAt : 0)) / 1000);
  const send = (event, extra = {}) => {
    const body = JSON.stringify({ event, path: location.pathname, referrer: document.referrer || null, ...extra });
    if (navigator.sendBeacon) navigator.sendBeacon(endpoint, body);
    else fetch(endpoint, { method: "POST", body, keepalive: true, credentials: "same-origin" }).catch(() => {});
  };
  send("page_view");
  setTimeout(() => { if (visibleSeconds() >= 10) send("visible_10s", { visible_seconds: visibleSeconds() }); }, 10000);
  setTimeout(() => { if (visibleSeconds() >= 20) send("visible_20s", { visible_seconds: visibleSeconds() }); }, 20000);
  document.addEventListener("click", (event) => {
    const link = event.target.closest("a[href]");
    if (!link) return;
    try {
      const target = new URL(link.href, location.href);
      if (target.origin === location.origin) send("internal_click", { target_path: target.pathname });
    } catch {}
  }, { capture: true });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") visibleStartedAt = Date.now();
    else if (visibleStartedAt) { visibleMilliseconds += Date.now() - visibleStartedAt; visibleStartedAt = null; }
  });
  addEventListener("pagehide", () => send("page_hidden", { visible_seconds: visibleSeconds() }));
})();

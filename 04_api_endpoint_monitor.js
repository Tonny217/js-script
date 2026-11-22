
// @name Universal API Monitor
// @version 1.0
// @match *://*/*

(() => {
  if (window.__pcapApiMonitor) return;
  window.__pcapApiMonitor = true;

  const originalFetch = window.fetch;

  window.fetch = function(...args) {
    const url = args[0]?.url || args[0];
    const method = args[1]?.method ||
      args[0]?.method || "GET";

    const start = performance.now();

    return originalFetch.apply(this, args).then(response => {
      console.log("[PCAP API]", {
        url: new URL(url, location.href).href,
        method,
        status: response.status,
        duration: Math.round(performance.now() - start) + "ms"
      });

      return response;
    });
  };

  console.log("[PCAP] API Monitor enabled");
})();

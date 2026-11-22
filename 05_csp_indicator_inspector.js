
// @name Universal CSP Inspector
// @version 1.0
// @match *://*/*

(() => {
  const policies = [...document.querySelectorAll(
    'meta[http-equiv="Content-Security-Policy"]'
  )].map(meta => meta.content);

  console.group("[PCAP] CSP Audit");

  console.log(
    "HTTPS:",
    location.protocol === "https:"
  );

  console.log(
    "Meta CSP policies:",
    policies.length ? policies : "None found"
  );

  console.log(
    "Check HTTP response headers for actual CSP policies."
  );

  console.groupEnd();
})();

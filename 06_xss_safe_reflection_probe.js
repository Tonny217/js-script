
// @name Universal XSS Safe Probe
// @version 1.0
// @match *://*/*

(() => {
  const params = new URLSearchParams(location.search);
  const text = document.body?.innerText || "";

  const results = [];

  for (const [key, value] of params.entries()) {
    if (!value || value.length > 160) continue;

    results.push({
      parameter: key,
      reflectedAsText: text.includes(value)
    });
  }

  console.group("[PCAP] XSS Reflection Audit");
  console.table(results);
  console.log(
    "Text reflection alone does not prove XSS."
  );
  console.groupEnd();
})();

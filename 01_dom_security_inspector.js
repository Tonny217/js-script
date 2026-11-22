
// @name Universal DOM Security Inspector
// @description Inspect potentially unsafe DOM APIs
// @version 1.0
// @match *://*/*

(() => {
  if (window.__pcapDomAudit) return;
  window.__pcapDomAudit = true;

  const patterns = [
    ["innerHTML", /\.innerHTML\b/g],
    ["outerHTML", /\.outerHTML\b/g],
    ["document.write", /\bdocument\.write\s*\(/g],
    ["eval", /\beval\s*\(/g],
    ["Function", /\bnew\s+Function\s*\(/g],
    ["insertAdjacentHTML", /\.insertAdjacentHTML\s*\(/g]
  ];

  const findings = [];

  document.querySelectorAll("script:not([src])")
    .forEach((script, index) => {
      const source = script.textContent || "";

      patterns.forEach(([name, regex]) => {
        regex.lastIndex = 0;
        const matches = source.match(regex);

        if (matches) {
          findings.push({
            script: index + 1,
            API: name,
            occurrences: matches.length
          });
        }
      });
    });

  console.group("[PCAP] DOM Audit");
  console.table(findings);
  console.groupEnd();
})();

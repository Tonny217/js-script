
 // @name PCAPdroid Advanced Web Security Scanner
 // @description Universal authorized web security assessment
 // @version 2.0
 // @match *://*/*

(() => {
  "use strict";

  if (window.__PCAP_ADVANCED_SCANNER__) return;
  window.__PCAP_ADVANCED_SCANNER__ = true;

  const findings = [];
  const add = (category, severity, detail) => {
    findings.push({
      category,
      severity,
      detail
    });
  };

  const report = {
    url: location.origin,
    scannedAt: new Date().toISOString(),
    findings
  };

  console.log("%c PCAPdroid Advanced Scanner ",
    "background:#111;color:#00ff99;font-size:16px;padding:8px");

  // 1. HTTPS CHECK
  if (location.protocol !== "https:") {
    add("Transport", "HIGH",
      "Page is not loaded over HTTPS.");
  }

  // 2. FORM SECURITY
  document.querySelectorAll("form").forEach((form, index) => {
    const password = form.querySelector(
      'input[type="password"]'
    );

    const action = new URL(
      form.getAttribute("action") || location.href,
      location.href
    );

    if (password) {
      if (action.protocol !== "https:") {
        add("Authentication", "HIGH",
          `Login form ${index + 1} submits over non-HTTPS.`);
      }

      if (form.method.toLowerCase() === "get") {
        add("Authentication", "MEDIUM",
          `Login form ${index + 1} uses GET.`);
      }

      if (!password.autocomplete) {
        add("Authentication", "INFO",
          `Login form ${index + 1} has no explicit autocomplete setting.`);
      }
    }

    if (action.origin !== location.origin) {
      add("Forms", "INFO",
        `Form ${index + 1} submits to another origin.`);
    }
  });

  // 3. COOKIE INSPECTION
  const cookieNames = document.cookie
    .split(";")
    .map(item => item.trim().split("=")[0])
    .filter(Boolean);

  add("Cookies", "INFO",
    `${cookieNames.length} JavaScript-visible cookies found.`);

  if (cookieNames.length) {
    add("Cookies", "INFO",
      "HttpOnly, Secure and SameSite attributes require response-header inspection.");
  }

  // 4. DOM XSS INDICATORS
  const dangerousPatterns = [
    ["innerHTML", /\.innerHTML\b/g],
    ["outerHTML", /\.outerHTML\b/g],
    ["document.write", /\bdocument\.write\s*\(/g],
    ["eval", /\beval\s*\(/g],
    ["insertAdjacentHTML", /\.insertAdjacentHTML\s*\(/g]
  ];

  document.querySelectorAll("script:not([src])")
    .forEach((script, index) => {
      const source = script.textContent || "";

      dangerousPatterns.forEach(([name, pattern]) => {
        pattern.lastIndex = 0;
        const matches = source.match(pattern);

        if (matches) {
          add("DOM XSS indicator", "INFO",
            `Inline script ${index + 1} references ${name} (${matches.length} occurrence(s)).`);
        }
      });
    });

  // 5. REFLECTED INPUT INDICATORS
  const pageText = document.body?.innerText || "";

  new URLSearchParams(location.search)
    .forEach((value, key) => {
      if (value && value.length <= 160 &&
          pageText.includes(value)) {
        add("XSS reflection", "INFO",
          `URL parameter "${key}" appears as visible page text. This is not proof of XSS.`);
      }
    });

  // 6. CSRF INDICATORS
  document.querySelectorAll("form").forEach((form, index) => {
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(
      form.method.toUpperCase()
    )) return;

    const token = form.querySelector(
      'input[name*="csrf" i], input[name*="token" i]'
    );

    if (!token) {
      add("CSRF", "INFO",
        `Form ${index + 1} has no obvious CSRF/token field. Protection may exist elsewhere.`);
    }
  });

  // 7. CORS INDICATORS
  if (location.protocol === "file:") {
    add("CORS", "INFO",
      "Local file origin detected.");
  }

  add("CORS", "INFO",
    "Inspect Access-Control-Allow-Origin and credential headers in network responses.");

  // 8. CSP INDICATORS
  const csp = document.querySelector(
    'meta[http-equiv="Content-Security-Policy"]'
  );

  if (!csp) {
    add("CSP", "INFO",
      "No CSP meta tag found. Check HTTP response headers before concluding CSP is absent.");
  } else {
    add("CSP", "INFO",
      "CSP meta policy found. Review its directives.");
  }

  // 9. API ENDPOINT DISCOVERY
  const endpoints = new Set();

  document.querySelectorAll(
    'script[src], img[src], link[href], iframe[src]'
  ).forEach(element => {
    const value = element.src || element.href;

    if (!value) return;

    try {
      const url = new URL(value, location.href);

      if (url.origin === location.origin) {
        endpoints.add(url.pathname);
      }
    } catch (_) {}
  });

  add("API discovery", "INFO",
    `${endpoints.size} same-origin resource paths discovered.`);

  // 10. OPEN REDIRECT INDICATORS
  const redirectNames = [
    "redirect", "redirect_uri", "return",
    "returnurl", "next", "url", "continue"
  ];

  const params = new URLSearchParams(location.search);

  redirectNames.forEach(name => {
    if (params.has(name)) {
      add("Open redirect indicator", "INFO",
        `Potential redirect parameter detected: ${name}. Not confirmed vulnerable.`);
    }
  });

  // 11. SENSITIVE INFORMATION INDICATORS
  const body = document.body?.innerText || "";

  const patterns = [
    ["Private key marker", /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/],
    ["AWS access key pattern", /\bAKIA[0-9A-Z]{16}\b/],
    ["Possible email addresses", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i]
  ];

  patterns.forEach(([name, regex]) => {
    if (regex.test(body)) {
      add("Information exposure", "MEDIUM",
        `${name} pattern detected. Verify manually; no matching value is displayed.`);
    }
  });

  // 12. SQL INJECTION INDICATORS
  add("SQL injection", "INFO",
    "No SQL injection payloads sent. Server-side parameterized-query testing is required.");

  // 13. SECURITY REPORT
  console.group("PCAPdroid Security Assessment");

  console.log("Website:", report.url);
  console.log("Date:", report.scannedAt);
  console.log("Findings:", findings.length);

  console.table(findings);

  const summary = findings.reduce((result, item) => {
    result[item.severity] = (result[item.severity] || 0) + 1;
    return result;
  }, {});

  console.log("Severity summary:", summary);

  console.groupEnd();

  // 14. EXPORT REPORT
  window.PCAPdroidSecurityReport = report;

  window.exportPCAPdroidReport = () => {
    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: "application/json" }
    );

    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "pcapdroid-security-report.json";
    link.click();

    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  };

  console.log(
    "Export report with: exportPCAPdroidReport()"
  );

  console.log("Assessment completed.");
})();

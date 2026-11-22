
// @name Universal Cookie Inspector
// @version 1.0
// @match *://*/*

(() => {
  const cookies = document.cookie
    .split(";")
    .map(c => c.trim())
    .filter(Boolean)
    .map(c => c.split("=")[0]);

  console.group("[PCAP] Cookie Audit");
  console.log("HTTPS:", location.protocol === "https:");
  console.log("Visible cookie names:", cookies);
  console.log("HttpOnly cookies are not visible to JavaScript.");
  console.log("Check Secure and SameSite in Set-Cookie response headers.");
  console.groupEnd();
})();

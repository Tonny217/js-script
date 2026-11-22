
// @name Universal Form Security Scanner
// @version 1.0
// @match *://*/*

(() => {
  const forms = [...document.forms];

  const results = forms.map((form, index) => {
    const password = form.querySelector(
      'input[type="password"]'
    );

    const action = new URL(
      form.getAttribute("action") || location.href,
      location.href
    );

    return {
      form: index + 1,
      method: form.method.toUpperCase(),
      login: !!password,
      action: action.href,
      crossOrigin: action.origin !== location.origin,
      autocomplete: password
        ? password.autocomplete
        : "N/A"
    };
  });

  console.group("[PCAP] Form Audit");
  console.table(results);
  console.groupEnd();
})();

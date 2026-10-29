const ERRORS = {
  invalid_email: "Enter a valid email address.",
  access_denied: "Gmail access was not granted, so the inbox could not be scanned.",
  state_mismatch: "The sign-in could not be verified. Please try again.",
  session_expired: "Your session expired. Please connect again.",
  oauth_failed: "Google sign-in failed. Please try again.",
};

const PHASES = {
  starting: "Connecting to Gmail…",
  listing: "Finding every email in your inbox…",
  reading: "Reading email senders and subjects…",
  discovering: "Working out which services you have accounts with…",
  checking_breaches: "Checking Have I Been Pwned…",
};

const $ = (id) => document.getElementById(id);
const views = ["connect-view", "scan-view", "error-view", "results-view"];
let pollTimer = null;

function show(view) {
  for (const id of views) $(id).hidden = id !== view;
}

// Builds an element with text content only, so email subjects and sender
// names (which anyone can write) are never interpreted as HTML.
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

const number = (n) => Number(n).toLocaleString();

async function refresh() {
  clearTimeout(pollTimer);
  let state;
  try {
    const response = await fetch("/api/session");
    state = await response.json();
  } catch {
    pollTimer = setTimeout(refresh, 3000);
    return;
  }

  if (!state.connected) {
    renderConnect();
    return;
  }

  const scan = state.scan;
  if (scan.status === "running") {
    renderScanning(scan);
    pollTimer = setTimeout(refresh, 1500);
  } else if (scan.status === "error") {
    $("error-message").textContent = scan.error;
    show("error-view");
  } else {
    renderResults(state, scan);
  }
}

function renderConnect() {
  const code = new URLSearchParams(location.search).get("error");
  $("connect-error").hidden = !code;
  $("connect-error").textContent = ERRORS[code] || "Something went wrong. Please try again.";
  show("connect-view");
}

function renderScanning(scan) {
  $("scan-email").textContent = scan.email || "";
  let text = PHASES[scan.phase] || "Scanning…";
  let percent = 0;

  if (scan.phase === "listing") {
    text += ` ${number(scan.done)} found so far.`;
  } else if (scan.phase === "reading" && scan.total) {
    percent = (scan.done / scan.total) * 100;
    text += ` ${number(scan.done)} of ${number(scan.total)}.`;
  } else if (scan.phase === "discovering" || scan.phase === "checking_breaches") {
    percent = 100;
  }

  $("scan-phase").textContent = text;
  $("scan-bar").style.width = `${percent}%`;
  show("scan-view");
}

function renderResults(state, scan) {
  $("results-email").textContent = scan.email;
  $("results-meta").textContent =
    `${number(scan.messages_scanned)} emails scanned · ${number(scan.accounts.length)} services found`;

  const requested = (state.requested_email || "").toLowerCase();
  const mismatch = requested && requested !== scan.email.toLowerCase();
  $("results-mismatch").hidden = !mismatch;
  $("results-mismatch").textContent = mismatch
    ? `You entered ${state.requested_email}, but Google connected ${scan.email}. Results are for ${scan.email}.`
    : "";

  renderAccounts(scan.accounts);
  renderEmailBreaches(scan.email_breaches);
  show("results-view");
}

function renderAccounts(accounts) {
  const body = $("accounts-body");
  body.replaceChildren();
  $("accounts-count").textContent = `(${number(accounts.length)})`;

  const breached = accounts.filter((a) => a.breach_check.known_breach).length;
  const unavailable = accounts.some((a) => a.breach_check.status === "unavailable");
  $("accounts-summary").textContent = unavailable
    ? "Service breach history could not be checked. Try scanning again later."
    : `${number(breached)} of these services have had a known data breach.`;

  if (!accounts.length) {
    const row = el("tr");
    const cell = el("td", "No services found in this inbox.", "muted");
    cell.colSpan = 5;
    row.append(cell);
    body.append(row);
    return;
  }

  for (const account of accounts) {
    const check = account.breach_check;
    const row = el("tr", null, check.known_breach ? "breached" : "");

    let history;
    if (check.status === "unavailable") {
      history = el("td", "Unavailable", "muted");
    } else if (check.known_breach) {
      history = el("td");
      for (const breach of check.breaches) {
        history.append(el("div", `Breached · ${breach.name} (${breach.breach_date})`));
      }
    } else {
      history = el("td", "No known breach", "muted");
    }

    row.append(
      el("td", account.service_name),
      el("td", account.domain),
      el("td", account.first_seen || "—"),
      el("td", account.evidence_subject),
      history,
    );
    body.append(row);
  }
}

function renderEmailBreaches(result) {
  const box = $("email-breaches");
  box.replaceChildren();

  if (result.status === "unavailable") {
    box.append(el("p", result.note, "notice"));
    return;
  }

  if (!result.breached) {
    box.append(el("p", `${result.email} was not found in any known breach.`));
    return;
  }

  box.append(el("p", `${result.email} appears in ${number(result.breaches.length)} known breaches.`));

  const table = el("table");
  const head = el("tr");
  for (const title of ["Breach", "Domain", "Date", "Data exposed"]) head.append(el("th", title));
  const thead = el("thead");
  thead.append(head);
  table.append(thead);

  const body = el("tbody");
  for (const breach of result.breaches) {
    const row = el("tr");
    row.append(
      el("td", breach.name),
      el("td", breach.domain || "—"),
      el("td", breach.breach_date),
      el("td", breach.data_exposed.join(", ")),
    );
    body.append(row);
  }
  table.append(body);

  const wrap = el("div", null, "table-wrap");
  wrap.append(table);
  box.append(wrap);
}

async function rescan() {
  await fetch("/api/scan", { method: "POST" });
  refresh();
}

async function disconnect() {
  await fetch("/api/disconnect", { method: "POST" });
  history.replaceState(null, "", "/app");
  refresh();
}

$("rescan").addEventListener("click", rescan);
$("error-retry").addEventListener("click", rescan);
$("disconnect").addEventListener("click", disconnect);
$("error-disconnect").addEventListener("click", disconnect);

refresh();

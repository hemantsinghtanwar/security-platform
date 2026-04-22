const state = {
  eventSource: null,
  logSource: null,
  csrfToken: null,
  events: [],
};

function cookieValue(name) {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${name}=`))
    ?.split("=")[1];
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  const csrf = state.csrfToken || cookieValue("csrf_token");
  if (csrf && ["POST", "PUT", "DELETE"].includes((options.method || "GET").toUpperCase())) {
    headers.set("X-CSRF-Token", decodeURIComponent(csrf));
  }
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(url, {
    credentials: "include",
    ...options,
    headers,
  });
  if (!response.ok) {
    const payload = await response.text();
    throw new Error(payload || `Request failed for ${url}`);
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

function showDashboard() {
  document.querySelectorAll(".panel.hidden").forEach((panel) => panel.classList.remove("hidden"));
  document.getElementById("loginPanel").classList.add("hidden");
  document.getElementById("authState").textContent = "Authenticated and streaming";
}

function showLogin() {
  document.getElementById("loginPanel").classList.remove("hidden");
  document.querySelectorAll(".main .panel").forEach((panel) => {
    if (panel.id !== "loginPanel") panel.classList.add("hidden");
  });
  document.getElementById("authState").textContent = "Authentication required";
}

function renderRows(containerId, rows, formatter) {
  const container = document.getElementById(containerId);
  if (!rows.length) {
    container.innerHTML = `<div class="row"><span>No data</span><span></span></div>`;
    return;
  }
  container.innerHTML = rows.map(formatter).join("");
}

function renderOverview(data) {
  document.getElementById("metricRps").textContent = Number(data.requests_per_second || 0).toFixed(1);
  document.getElementById("metricConnections").textContent = data.active_connections || 0;
  document.getElementById("metricBlocked").textContent = data.blocked_ips || 0;
  document.getElementById("metricEvents").textContent = data.recent_events || 0;
  document.getElementById("metricCpu").textContent = `${data.cpu_percent || 0}%`;
  document.getElementById("metricMemory").textContent = `${data.memory_percent || 0}%`;
  document.getElementById("metricDisk").textContent = `${data.disk_percent || 0}%`;
  document.getElementById("wpXmlrpc").textContent = data.wordpress_insights?.xmlrpc_attacks || 0;
  document.getElementById("wpLogins").textContent = data.wordpress_insights?.wp_login_bruteforce || 0;
  document.getElementById("mailEvents").textContent = data.mail_insights?.mail_events || 0;
  document.getElementById("mailOutbound").textContent = data.mail_insights?.outbound_keys || 0;

  renderRows("topAttackers", data.top_attackers || [], (row) => `
    <div class="row"><span>${row.ip}</span><strong>${row.count}</strong></div>
  `);
  renderRows("attackTypes", data.attack_counts || [], (row) => `
    <div class="row"><span>${row.event_type}</span><strong>${row.count}</strong></div>
  `);
}

function renderTimeline(events) {
  const container = document.getElementById("eventTimeline");
  if (!events.length) {
    container.innerHTML = `<div class="timeline-item"><p>No events found.</p></div>`;
    return;
  }
  container.innerHTML = events
    .map(
      (event) => `
      <article class="timeline-item">
        <header>
          <strong>${event.summary}</strong>
          <span class="badge ${event.severity}">${event.severity}</span>
        </header>
        <p>${event.message}</p>
        <div class="row"><span>${event.service}</span><span>${event.created_at}</span></div>
        <div class="row"><span>${event.ip || "N/A"}</span><span>${event.action_taken || "observed"}</span></div>
        <code>${event.sample_log}</code>
      </article>
    `
    )
    .join("");
}

function renderBlocked(blocks) {
  renderRows("blockedTable", blocks.slice(0, 15), (row) => `
    <div class="row">
      <span>${row.ip}</span>
      <button data-ip="${row.ip}" class="ghost-button unblock-button">Unblock</button>
    </div>
  `);
  document.querySelectorAll(".unblock-button").forEach((button) => {
    button.onclick = async () => {
      await api(`/api/v1/blocks/${button.dataset.ip}`, { method: "DELETE" });
      await refreshBlocks();
    };
  });
}

function renderRecipients(recipients) {
  renderRows("recipientList", recipients, (row) => `
    <div class="row">
      <span>${row.email}</span>
      <button data-id="${row.id}" class="ghost-button recipient-delete">Remove</button>
    </div>
  `);
  document.querySelectorAll(".recipient-delete").forEach((button) => {
    button.onclick = async () => {
      await api(`/api/v1/settings/recipients/${button.dataset.id}`, { method: "DELETE" });
      await refreshRecipients();
    };
  });
}

async function refreshOverview() {
  renderOverview(await api("/api/v1/overview"));
}

async function refreshEvents(filters = {}) {
  const params = new URLSearchParams(filters);
  const events = await api(`/api/v1/events?${params.toString()}`);
  state.events = events;
  renderTimeline(events);
}

async function refreshBlocks() {
  renderBlocked(await api("/api/v1/blocks"));
}

async function refreshRecipients() {
  renderRecipients(await api("/api/v1/settings/recipients"));
}

async function refreshSMTP() {
  const smtp = await api("/api/v1/settings/email");
  const form = document.getElementById("smtpForm");
  form.host.value = smtp.host || "";
  form.port.value = smtp.port || 25;
  form.sender.value = smtp.sender || "";
  form.username.value = smtp.username || "";
  form.password.value = "";
  form.use_tls.checked = Boolean(smtp.use_tls);
  form.use_starttls.checked = Boolean(smtp.use_starttls);
}

async function refreshLogSources() {
  const sources = await api("/api/v1/log-sources");
  const select = document.getElementById("logSource");
  const all = Object.values(sources).flat();
  select.innerHTML = `<option value="">All sources</option>${all
    .map((source) => `<option value="${source}">${source}</option>`)
    .join("")}`;
}

function connectEventStream() {
  if (state.eventSource) {
    state.eventSource.close();
  }
  const source = new EventSource("/api/v1/events/stream", { withCredentials: true });
  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    state.events.unshift(payload);
    renderTimeline(state.events.slice(0, 100));
    refreshOverview();
    refreshBlocks();
  };
  state.eventSource = source;
}

function connectLogStream() {
  if (state.logSource) {
    state.logSource.close();
  }
  const selected = document.getElementById("logSource").value;
  const url = selected
    ? `/api/v1/logs/stream?source=${encodeURIComponent(selected)}`
    : "/api/v1/logs/stream";
  const source = new EventSource(url, { withCredentials: true });
  const viewer = document.getElementById("logViewer");
  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    viewer.textContent = `${payload.created_at} ${payload.source}\n${payload.line}\n\n${viewer.textContent}`.slice(0, 40000);
  };
  state.logSource = source;
}

async function bootstrap() {
  try {
    const me = await api("/api/v1/auth/me");
    state.csrfToken = decodeURIComponent(cookieValue("csrf_token") || "");
    showDashboard();
    await Promise.all([
      refreshOverview(),
      refreshEvents(),
      refreshBlocks(),
      refreshRecipients(),
      refreshSMTP(),
      refreshLogSources(),
    ]);
    connectEventStream();
    connectLogStream();
    setInterval(refreshOverview, 15000);
    return me;
  } catch {
    showLogin();
    return null;
  }
}

document.getElementById("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  try {
    const result = await api("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: form.get("username"),
        password: form.get("password"),
      }),
    });
    state.csrfToken = result.csrf_token;
    document.getElementById("loginError").textContent = "";
    await bootstrap();
  } catch (error) {
    document.getElementById("loginError").textContent = "Login failed. Check credentials and try again.";
  }
});

document.getElementById("logoutButton").addEventListener("click", async () => {
  await api("/api/v1/auth/logout", { method: "POST" });
  if (state.eventSource) state.eventSource.close();
  if (state.logSource) state.logSource.close();
  showLogin();
});

document.getElementById("filterForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  await refreshEvents({
    ip: form.get("ip") || "",
    domain: form.get("domain") || "",
    service: form.get("service") || "",
    severity: form.get("severity") || "",
  });
});

document.getElementById("reloadLogs").addEventListener("click", connectLogStream);
document.getElementById("logSource").addEventListener("change", connectLogStream);

document.getElementById("smtpForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  await api("/api/v1/settings/email", {
    method: "PUT",
    body: JSON.stringify({
      host: form.host.value,
      port: Number(form.port.value),
      sender: form.sender.value,
      username: form.username.value || null,
      password: form.password.value || null,
      use_tls: form.use_tls.checked,
      use_starttls: form.use_starttls.checked,
    }),
  });
});

document.getElementById("recipientForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  await api("/api/v1/settings/recipients", {
    method: "POST",
    body: JSON.stringify({
      email: form.email.value,
      name: form.name.value || null,
    }),
  });
  form.reset();
  await refreshRecipients();
});

document.getElementById("blockForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  await api("/api/v1/blocks", {
    method: "POST",
    body: JSON.stringify({
      ip: form.ip.value,
      reason: form.reason.value,
      duration_minutes: Number(form.duration_minutes.value || 60),
      permanent: form.permanent.checked,
    }),
  });
  form.reset();
  await refreshBlocks();
});

bootstrap();

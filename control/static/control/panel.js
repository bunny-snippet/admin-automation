(() => {
  "use strict";

  const app = document.getElementById("panel-app");
  const content = document.getElementById("panel-content");
  const pageTitle = document.getElementById("page-title");
  const breadcrumb = document.getElementById("page-breadcrumb");
  const refreshButton = document.getElementById("refresh-button");
  const syncLabel = document.getElementById("sync-label");
  const dialog = document.getElementById("detail-dialog");
  const detailTitle = document.getElementById("detail-title");
  const detailContent = document.getElementById("detail-content");

  const endpoints = {
    overview: app.dataset.overviewUrl,
    domains: app.dataset.domainUrl,
    suspicious: app.dataset.suspiciousUrl,
    export: app.dataset.domainExportUrl,
    resource: app.dataset.resourceUrl,
  };
  const labels = {
    overview: ["Overview", "Operations overview"],
    domains: ["Domain activity", "Domain activity intelligence"],
    suspicious: ["Suspicious activity", "Monitored-domain alerts"],
    devices: ["Devices", "Devices and access"],
    configurations: ["Config bundles", "Configuration bundles"],
    groups: ["Browser groups", "Browser group mapping"],
    providers: ["Providers", "Proxy providers"],
    "proxy-catalog": ["Proxy catalog", "Country proxy catalog"],
    extensions: ["Extensions", "Managed extensions"],
    "proxy-pools": ["Proxy pools", "Proxy pool health"],
    "proxy-inventory": ["Proxy inventory", "Proxy inventory"],
    "proxy-jobs": ["Generation jobs", "Proxy generation jobs"],
    reservations: ["Reservations", "Proxy reservations"],
    "profile-activity": ["Profile activity", "Profile lifecycle activity"],
    "access-audit": ["Access audit", "Bootstrap access audit"],
  };
  const state = {
    route: "overview",
    resourcePage: 1,
    resourceQuery: "",
    domainPage: 1,
    domainFilters: { range: "7d", sort: "last_seen", page_size: "25" },
  };

  const e = (value) => String(value ?? "").replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]),
  );
  const number = (value) => new Intl.NumberFormat("en-IN").format(Number(value || 0));
  const formatDate = (value) => {
    if (!value) return "?";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return e(value);
    return new Intl.DateTimeFormat("en-IN", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(parsed);
  };
  const duration = (seconds) => {
    const total = Number(seconds || 0);
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const rest = total % 60;
    return [hours ? `${hours}h` : "", minutes ? `${minutes}m` : "", `${rest}s`]
      .filter(Boolean).join(" ");
  };
  const truncate = (value, length = 34) => {
    const text = String(value ?? "");
    return text.length > length ? `${text.slice(0, length)}?` : text;
  };
  const statusClass = (value) => {
    const text = String(value ?? "").toLowerCase();
    if (["true", "active", "available", "ready", "completed", "profile_opened", "allowed"].includes(text)) return "is-success";
    if (["false", "failed", "error", "denied", "inactive"].includes(text)) return "is-danger";
    if (["queued", "pending", "reserved", "generating", "partial"].includes(text)) return "is-warning";
    return "is-neutral";
  };
  const statusPill = (value) => {
    const label = typeof value === "boolean" ? (value ? "Yes" : "No") : (value || "Unknown");
    return `<span class="status-pill ${statusClass(value)}">${e(label)}</span>`;
  };

  async function api(url) {
    syncLabel.textContent = "Refreshing";
    const response = await fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (response.redirected && response.url.includes("login")) {
      window.location.assign(response.url);
      throw new Error("Session expired");
    }
    const type = response.headers.get("content-type") || "";
    if (!response.ok || !type.includes("application/json")) {
      throw new Error(`Request failed with status ${response.status}`);
    }
    const payload = await response.json();
    syncLabel.textContent = "Live data";
    return payload;
  }

  function loading() {
    content.innerHTML = `
      <div class="loading-state">
        <div class="loading-line"></div>
        <div class="loading-grid">
          <div class="loading-card"></div><div class="loading-card"></div>
          <div class="loading-card"></div><div class="loading-card"></div>
        </div>
        <div class="loading-table"></div>
      </div>`;
  }

  function showError(error) {
    syncLabel.textContent = "Load failed";
    const template = document.getElementById("error-template");
    content.replaceChildren(template.content.cloneNode(true));
    content.querySelector("[data-retry]")?.addEventListener("click", loadCurrent);
    console.error(error);
  }

  function metricCard(label, value, note) {
    return `
      <article class="metric-card">
        <div class="metric-label">${e(label)}</div>
        <div class="metric-value">${number(value)}</div>
        <div class="metric-note">${e(note)}</div>
      </article>`;
  }

  function domainTable(rows, compact = false) {
    if (!rows.length) {
      return `<div class="empty-state"><h2>No domain activity found</h2><p>No records match the selected period and filters.</p></div>`;
    }
    return `
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr>
            <th>Domain</th><th>Device</th><th>Office</th><th>Profile</th>
            ${compact ? "" : "<th>Group</th><th>Session</th>"}
            <th>Visits</th><th>Last visited</th><th></th>
          </tr></thead>
          <tbody>
            ${rows.map((row) => `
              <tr>
                <td><span class="cell-primary">${e(row.domain)}</span></td>
                <td title="${e(row.device_id)}">
                  <span class="cell-primary">${e(row.client_name)}</span>
                  <div class="cell-muted">${e(row.ipv4)}</div>
                </td>
                <td>${e(row.office_name)} / sys_${e(row.system_number)}</td>
                <td title="${e(row.profile_id)}">
                  <span class="cell-primary">${e(row.profile_name || "Unnamed")}</span>
                  <div class="cell-muted mono">${e(truncate(row.profile_id, 22))}</div>
                </td>
                ${compact ? "" : `
                  <td><span class="mono">${e(row.group_id || "?")}</span></td>
                  <td><span class="mono">${e(truncate(row.session_id, 17))}</span></td>`}
                <td>${number(row.visit_count)}</td>
                <td>${formatDate(row.last_visited_at)}</td>
                <td><button class="link-button" data-domain-detail="${row.id}">Details</button></td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }

  function bindDomainDetails() {
    content.querySelectorAll("[data-domain-detail]").forEach((button) => {
      button.addEventListener("click", () => showDomainDetail(button.dataset.domainDetail));
    });
  }

  async function loadOverview() {
    const data = await api(endpoints.overview);
    const jobs = Object.entries(data.job_status || {});
    const pools = Object.entries(data.pool_status || {});
    content.innerHTML = `
      <div class="page-intro">
        <div>
          <span class="eyebrow">Live control plane</span>
          <h2>Everything important, at a glance</h2>
          <p>Device authorization, profile execution, domain evidence and proxy capacity from the last 24 hours.</p>
        </div>
        <span class="cell-muted">Updated ${formatDate(data.generated_at)}</span>
      </div>
      <div class="metric-grid">
        ${metricCard("Active devices", data.cards.active_devices, `${number(data.cards.online_24h)} seen in 24 hours`)}
        ${metricCard("Profiles opened", data.cards.profiles_opened_24h, "Completed in the last 24 hours")}
        ${metricCard("Domain visits", data.cards.domain_visits_24h, `${number(data.cards.unique_domains_24h)} unique domains`)}
        ${metricCard("Available proxies", data.cards.available_proxies, "Ready in managed pools")}
        ${metricCard("Suspicious activity", data.cards.suspicious_activity_24h, "Monitored-domain matches")}
      </div>
      <div class="dashboard-grid">
        <div class="dashboard-stack">
          <article class="panel-card">
            <div class="panel-header">
              <div><h3>Recent domain activity</h3><p>Latest profile browsing evidence</p></div>
              <button class="link-button" data-go="domains">View all</button>
            </div>
            <div class="panel-body-flush">${domainTable(data.recent_domains, true)}</div>
          </article>
          <article class="panel-card">
            <div class="panel-header"><div><h3>Management</h3><p>Core configuration areas</p></div></div>
            <div class="panel-body management-grid">
              ${data.management.map((item) => `
                <button class="management-card" data-go="${e(item.key)}">
                  <div><strong>${e(item.label)}</strong><span>${e(item.description)}</span></div>
                  <strong>${number(item.count)}</strong>
                </button>`).join("")}
            </div>
          </article>
        </div>
        <div class="dashboard-stack">
          <article class="panel-card">
            <div class="panel-header"><div><h3>Offices</h3><p>Authorized device coverage</p></div></div>
            <div class="panel-body office-list">
              ${data.offices.length ? data.offices.map((office) => `
                <div class="office-row">
                  <div><strong>${e(office.office_name)}</strong><span>${number(office.active_devices)} active of ${number(office.devices)}</span></div>
                  <span>${office.last_seen_at ? formatDate(office.last_seen_at) : "Never seen"}</span>
                </div>`).join("") : "<div class='cell-muted'>No offices configured.</div>"}
            </div>
          </article>
          <article class="panel-card">
            <div class="panel-header"><div><h3>System health</h3><p>Jobs, inventory and access</p></div></div>
            <div class="panel-body status-list">
              ${jobs.map(([key, value]) => `<div class="status-row"><span>Jobs ? ${e(key)}</span><strong>${number(value)}</strong></div>`).join("") || "<div class='status-row'><span>Jobs</span><strong>0</strong></div>"}
              ${pools.map(([key, value]) => `<div class="status-row"><span>Proxies ? ${e(key)}</span><strong>${number(value)}</strong></div>`).join("")}
              <div class="status-row"><span>Access allowed ? 24h</span><strong>${number(data.bootstrap_status.allowed)}</strong></div>
              <div class="status-row"><span>Access denied ? 24h</span><strong>${number(data.bootstrap_status.denied)}</strong></div>
            </div>
          </article>
        </div>
      </div>`;
    bindDomainDetails();
    content.querySelectorAll("[data-go]").forEach((item) => {
      item.addEventListener("click", () => navigate(item.dataset.go));
    });
  }

  function domainParams() {
    const params = new URLSearchParams();
    Object.entries(state.domainFilters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    params.set("page", String(state.domainPage));
    return params;
  }

  function dateFilterOptions(filters) {
    return '<div class="field"><label>From date & time</label><input type="datetime-local" name="from" value="' + e(filters.from || "") + '"></div><div class="field"><label>To date & time</label><input type="datetime-local" name="to" value="' + e(filters.to || "") + '"></div>';
  }

  function filterOptions(data) {
    const filters = state.domainFilters;
    return `
      <div class="field field-wide"><label>Search everything</label><input name="q" value="${e(filters.q || "")}" placeholder="Domain, device, IP, profile or session"></div>
      <div class="field"><label>Office</label><select name="office"><option value="">All offices</option>
        ${data.options.offices.map((value) => `<option value="${e(value)}" ${filters.office === value ? "selected" : ""}>${e(value)}</option>`).join("")}
      </select></div>
      <div class="field"><label>Device</label><select name="client"><option value="">All devices</option>
        ${data.options.clients.map((row) => `<option value="${row.id}" ${String(filters.client || "") === String(row.id) ? "selected" : ""}>${e(row.office_name)} ? sys_${e(row.system_number)} ? ${e(row.name)}</option>`).join("")}
      </select></div>
      <div class="field"><label>Group</label><select name="group"><option value="">All groups</option>
        ${data.options.groups.map((value) => `<option value="${e(value)}" ${filters.group === value ? "selected" : ""}>${e(value)}</option>`).join("")}
      </select></div>
      <div class="field"><label>Domain contains</label><input name="domain" value="${e(filters.domain || "")}" placeholder="example.com"></div>
      ${dateFilterOptions(filters)}
      <div class="field"><label>Sort by</label><select name="sort">
        ${[["last_seen","Latest visit"],["visits","Most visits"],["domain","Domain A?Z"],["device","Device"],["first_seen","First visit"]].map(([value,label]) => `<option value="${value}" ${filters.sort === value ? "selected" : ""}>${label}</option>`).join("")}
      </select></div>
      <button class="button button-primary" type="submit">Apply filters</button>
      <button class="button button-secondary" type="button" data-clear-filters>Clear</button>`;
  }

  async function loadDomains() {
    const params = domainParams();
    const data = await api(`${endpoints.domains}?${params}`);
    const maxVisits = Math.max(1, ...data.top_domains.map((row) => Number(row.visits || 0)));
    content.innerHTML = `
      <div class="page-intro">
        <div>
          <span class="eyebrow">Audit intelligence</span>
          <h2>Domain activity</h2>
          <p>Precise domain-level evidence by office, device, profile, group and browser session. Query strings and sensitive URL paths are never stored here.</p>
        </div>
        <a class="button button-secondary" href="${endpoints.export}?${params}">Export CSV</a>
      </div>
      <div class="subnav" role="group" aria-label="Date range">
        ${[["24h","24 hours"],["7d","7 days"],["30d","30 days"],["90d","90 days"]].map(([value,label]) => `<button data-range="${value}" class="${state.domainFilters.range === value ? "is-active" : ""}">${label}</button>`).join("")}
      </div>
      <form class="toolbar" id="domain-filters">${filterOptions(data)}</form>
      <div class="metric-grid">
        ${metricCard("Total visits", data.metrics.visits, `${number(data.metrics.records)} stored records`)}
        ${metricCard("Unique domains", data.metrics.unique_domains, "Across the filtered period")}
        ${metricCard("Devices", data.metrics.devices, `${number(data.metrics.profiles)} profiles`)}
        ${metricCard("Sessions", data.metrics.sessions, "Distinct browsing sessions")}
      </div>
      <div class="domain-layout">
        <article class="panel-card">
          <div class="panel-header"><div><h3>Activity records</h3><p>${number(data.pagination.total)} matching records</p></div></div>
          <div class="panel-body-flush">${domainTable(data.rows)}</div>
          ${pagination(data.pagination, "domains")}
        </article>
        <article class="panel-card">
          <div class="panel-header"><div><h3>Top domains</h3><p>Ranked by visits</p></div></div>
          <div class="panel-body ranking-list">
            ${data.top_domains.length ? data.top_domains.map((row) => `
              <div class="ranking-row">
                <div class="ranking-copy"><strong title="${e(row.domain)}">${e(row.domain)}</strong><span>${number(row.sessions)} sessions ? ${number(row.clients)} devices</span></div>
                <div class="ranking-value">${number(row.visits)}</div>
                <div class="ranking-bar"><span style="width:${Math.max(3, Math.round(Number(row.visits || 0) / maxVisits * 100))}%"></span></div>
              </div>`).join("") : "<div class='cell-muted'>No data in this period.</div>"}
          </div>
        </article>
      </div>`;
    bindDomainDetails();
    document.querySelectorAll("[data-range]").forEach((button) => {
      button.addEventListener("click", () => {
        state.domainFilters.range = button.dataset.range;
        delete state.domainFilters.from;
        delete state.domainFilters.to;
        state.domainPage = 1;
        loadCurrent();
      });
    });
    document.getElementById("domain-filters").addEventListener("submit", (event) => {
      event.preventDefault();
      const values = new FormData(event.currentTarget);
      ["q", "office", "client", "group", "domain", "from", "to", "sort"].forEach((key) => {
        const value = String(values.get(key) || "").trim();
        if (value) state.domainFilters[key] = value;
        else delete state.domainFilters[key];
      });
      state.domainPage = 1;
      loadCurrent();
    });
    content.querySelector("[data-clear-filters]").addEventListener("click", () => {
      state.domainFilters = { range: "7d", sort: "last_seen", page_size: "25" };
      state.domainPage = 1;
      loadCurrent();
    });
    bindPagination("domains");
  }

  function pagination(data, type) {
    return `
      <div class="pagination">
        <span>Page ${number(data.page)} of ${number(data.pages)} ? ${number(data.total)} records</span>
        <div class="pagination-actions">
          <button class="button button-secondary" data-page-type="${type}" data-page="${data.page - 1}" ${data.has_previous ? "" : "disabled"}>Previous</button>
          <button class="button button-secondary" data-page-type="${type}" data-page="${data.page + 1}" ${data.has_next ? "" : "disabled"}>Next</button>
        </div>
      </div>`;
  }

  function bindPagination(type) {
    content.querySelectorAll(`[data-page-type="${type}"]`).forEach((button) => {
      button.addEventListener("click", () => {
        const value = Number(button.dataset.page);
        if (type === "domains" || type === "suspicious") state.domainPage = value;
        else state.resourcePage = value;
        loadCurrent();
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    });
  }

  function renderResourceCell(row, column) {
    const value = row[column.key];
    if (column.type === "date") return formatDate(value);
    if (column.type === "status") return statusPill(value);
    if (column.type === "action") return `<a class="link-button" href="${e(value)}">Manage</a>`;
    const mono = /(^id$|_id$|device_id|ipv4|exit_ip)/.test(column.key) ? " mono" : "";
    return `<span class="${mono}" title="${e(value)}">${e(value === "" || value == null ? "?" : truncate(value, 55))}</span>`;
  }

  async function loadResource() {
    const url = endpoints.resource.replace("__resource__", encodeURIComponent(state.route));
    const params = new URLSearchParams({
      page: String(state.resourcePage),
      page_size: "25",
      q: state.resourceQuery,
    });
    const data = await api(`${url}?${params}`);
    content.innerHTML = `
      <div class="resource-header">
        <div>
          <span class="eyebrow">Management</span>
          <h2>${e(data.title)}</h2>
          <p>${e(data.description)}</p>
        </div>
        <div class="resource-actions">
          <input class="search-input" id="resource-search" value="${e(state.resourceQuery)}" placeholder="Search this section">
          <button class="button button-secondary" id="resource-search-button">Search</button>
          <a class="button button-primary" href="${e(data.admin_url)}">Manage in Admin</a>
        </div>
      </div>
      <article class="panel-card">
        <div class="panel-header"><div><h3>Records</h3><p>${number(data.pagination.total)} total</p></div></div>
        <div class="panel-body-flush">
          ${data.rows.length ? `
            <div class="table-wrap"><table class="data-table">
              <thead><tr>${data.columns.map((column) => `<th>${e(column.label)}</th>`).join("")}</tr></thead>
              <tbody>${data.rows.map((row) => `<tr>${data.columns.map((column) => `<td>${renderResourceCell(row, column)}</td>`).join("")}</tr>`).join("")}</tbody>
            </table></div>` : `<div class="empty-state"><h2>No records found</h2><p>Try another search or create the first record in Django Admin.</p></div>`}
        </div>
        ${pagination(data.pagination, "resource")}
      </article>`;
    const search = () => {
      state.resourceQuery = document.getElementById("resource-search").value.trim();
      state.resourcePage = 1;
      loadCurrent();
    };
    document.getElementById("resource-search-button").addEventListener("click", search);
    document.getElementById("resource-search").addEventListener("keydown", (event) => {
      if (event.key === "Enter") search();
    });
    bindPagination("resource");
  }

  async function showDomainDetail(id) {
    detailTitle.textContent = "Loading activity?";
    detailContent.innerHTML = "<div class='loading-table'></div>";
    dialog.showModal();
    try {
      const data = await api(`${endpoints.domains}${encodeURIComponent(id)}/`);
      const row = data.activity;
      detailTitle.textContent = row.domain;
      const fields = [
        ["Device", row.client_name], ["Office / system", `${row.office_name} / sys_${row.system_number}`],
        ["Public IP", row.ipv4], ["Device ID", row.device_id],
        ["Group ID", row.group_id || "?"], ["Profile name", row.profile_name || "?"],
        ["Profile ID", row.profile_id], ["Browser ID", row.browser_id || "?"],
        ["Session ID", row.session_id], ["Visits", number(row.visit_count)],
        ["First visited", formatDate(row.first_visited_at)], ["Last visited", formatDate(row.last_visited_at)],
        ["Session started", formatDate(row.session_started_at)], ["Session ended", formatDate(row.session_ended_at)],
        ["Session duration", duration(row.session_duration_seconds)],
        ["Job / reservation", `${row.job_id || "?"} / ${row.reservation_id || "?"}`],
      ];
      detailContent.innerHTML = `
        <div class="detail-grid">
          ${fields.map(([label, value]) => `<div class="detail-field"><span>${e(label)}</span><strong>${e(value)}</strong></div>`).join("")}
        </div>
        <div class="detail-section">
          <div class="panel-header"><div><h3>Domains in the same profile session</h3><p>${number(data.session_domains.length)} unique domains</p></div><a class="link-button" href="${e(row.admin_url)}">Open record in Admin</a></div>
          <div class="table-wrap"><table class="data-table">
            <thead><tr><th>Domain</th><th>Visits</th><th>First visited</th><th>Last visited</th></tr></thead>
            <tbody>${data.session_domains.map((item) => `<tr><td class="cell-primary">${e(item.domain)}</td><td>${number(item.visit_count)}</td><td>${formatDate(item.first_visited_at)}</td><td>${formatDate(item.last_visited_at)}</td></tr>`).join("")}</tbody>
          </table></div>
        </div>`;
    } catch (error) {
      detailTitle.textContent = "Activity unavailable";
      detailContent.innerHTML = `<div class="empty-state"><p>${e(error.message)}</p></div>`;
    }
  }

  async function loadSuspicious() {
    const params = domainParams();
    const data = await api(`${endpoints.suspicious}?${params}`);
    content.innerHTML = `
      <div class="page-intro">
        <div>
          <span class="eyebrow">Monitored-domain alerts</span>
          <h2>Suspicious activity</h2>
          <p>Every monitored-domain match, with the device, office, profile, group, IP and exact timestamps.</p>
        </div>
        <a class="button button-secondary" href="${e(data.monitor_admin_url)}">Manage monitored domains</a>
      </div>
      <div class="subnav" role="group" aria-label="Date range">
        ${[["24h","24 hours"],["7d","7 days"],["30d","30 days"],["90d","90 days"]].map(([value,label]) => `<button data-range="${value}" class="${state.domainFilters.range === value ? "is-active" : ""}">${label}</button>`).join("")}
      </div>
      <form class="toolbar" id="suspicious-filters">${dateFilterOptions(state.domainFilters)}
        <button class="button button-primary" type="submit">Apply filters</button>
        <button class="button button-secondary" type="button" data-clear-suspicious-filters>Clear</button>
      </form>
      <div class="metric-grid">
        ${metricCard("Alerts", data.metrics.records, `${number(data.metrics.domains)} monitored domains`)}
        ${metricCard("Visits", data.metrics.visits, `${number(data.metrics.clients)} devices`)}
        ${metricCard("Profiles", data.metrics.profiles, `${number(data.metrics.sessions)} sessions`)}
      </div>
      <article class="panel-card">
        <div class="panel-header"><div><h3>Monitored-domain matches</h3><p>${number(data.pagination.total)} records</p></div></div>
        <div class="panel-body-flush">${domainTable(data.rows)}</div>
        ${pagination(data.pagination, "suspicious")}
      </article>`;
    bindDomainDetails();
    document.querySelectorAll("[data-range]").forEach((button) => {
      button.addEventListener("click", () => {
        state.domainFilters.range = button.dataset.range;
        delete state.domainFilters.from;
        delete state.domainFilters.to;
        state.domainPage = 1;
        loadCurrent();
      });
    });
    document.getElementById("suspicious-filters").addEventListener("submit", (event) => {
      event.preventDefault();
      const values = new FormData(event.currentTarget);
      ["from", "to"].forEach((key) => {
        const value = String(values.get(key) || "").trim();
        if (value) state.domainFilters[key] = value;
        else delete state.domainFilters[key];
      });
      state.domainFilters.range = "custom";
      state.domainPage = 1;
      loadCurrent();
    });
    content.querySelector("[data-clear-suspicious-filters]").addEventListener("click", () => {
      state.domainFilters = { range: "7d", sort: "last_seen", page_size: "25" };
      state.domainPage = 1;
      loadCurrent();
    });
    bindPagination("suspicious");
  }

  async function loadCurrent() {
    loading();
    refreshButton.disabled = true;
    try {
      if (state.route === "overview") await loadOverview();
      else if (state.route === "domains") await loadDomains();
      else if (state.route === "suspicious") await loadSuspicious();
      else await loadResource();
    } catch (error) {
      showError(error);
    } finally {
      refreshButton.disabled = false;
    }
  }

  function navigate(route, updateHash = true) {
    if (!labels[route]) route = "overview";
    state.route = route;
    state.resourcePage = 1;
    document.querySelectorAll(".nav-item").forEach((item) => {
      item.classList.toggle("is-active", item.dataset.route === route);
    });
    breadcrumb.textContent = labels[route][0];
    pageTitle.textContent = labels[route][1];
    if (updateHash) history.replaceState(null, "", `#${route}`);
    document.body.classList.remove("sidebar-open");
    loadCurrent();
  }

  document.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", () => navigate(item.dataset.route));
  });
  refreshButton.addEventListener("click", loadCurrent);
  document.querySelector("[data-sidebar-open]").addEventListener("click", () => document.body.classList.add("sidebar-open"));
  document.querySelector("[data-sidebar-close]").addEventListener("click", () => document.body.classList.remove("sidebar-open"));
  document.querySelector("[data-dialog-close]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  window.addEventListener("hashchange", () => navigate(location.hash.slice(1), false));

  navigate(location.hash.slice(1) || "overview", false);
})();

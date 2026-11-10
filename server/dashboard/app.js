"use strict";
const $ = (id) => document.getElementById(id);
const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const S = { vehicles: [], profiles: [], tel: {}, conn: {}, seen: {}, prov: {}, sel: null, alerts: [], muted: false, lastSpeak: 0 };

/* ---------- labels ---------- */
const STATUS = {
  live: ["Live", "ok"], offline: ["Offline", "off"],
  awaiting_device: ["Awaiting device", "wait"], profile_unsupported: ["Profile not supported", "bad"],
};
const ATTACK_LABEL = {
  normal: "Normal", dos: "DoS flood", fuzzy: "Fuzzing (random IDs)", spoofing: "Spoofing", tunnel_attack: "Tunnel attack",
};
const ALERT_LABEL = {
  dos: "DoS flood", fuzzy: "Fuzzing", spoofing_rpm: "RPM spoofing", spoofing_gear: "Gear spoofing",
  spoofing_steering: "Steering spoofing", auth_fail: "Auth failure", replay: "Replay", tamper: "Tampered packet",
  overheat: "Overheat", low_battery: "Low battery", sensor_inconsistency: "Sensor inconsistency",
  forecast_overheat: "Overheat forecast", forecast_battery: "Battery forecast", health_anomaly: "Health anomaly",
};

/* ---------- helpers ---------- */
const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const fmt = (v, d = 0) => (num(v) === null ? "—" : v.toFixed(d));
const colorFor = (v, invert) => { // v 0..100; invert => high is bad
  if (num(v) === null) return css("--muted");
  const g = invert ? 100 - v : v;
  return g >= 75 ? css("--ok") : g >= 45 ? css("--warn") : css("--bad");
};
function esc(s) { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
const ingestUrl = () => (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/ingest";

function arcGauge(cv, value, max, color, label) {
  const c = cv.getContext("2d"), w = cv.width, h = cv.height;
  c.clearRect(0, 0, w, h);
  const cx = w / 2, cy = h * 0.68, r = Math.min(w / 2, h * 0.68) - 10;
  const a0 = Math.PI * 0.8, a1 = Math.PI * 2.2;
  c.lineWidth = 12; c.lineCap = "round";
  c.strokeStyle = css("--panel2"); c.beginPath(); c.arc(cx, cy, r, a0, a1); c.stroke();
  const f = Math.max(0, Math.min(1, (num(value) ?? 0) / max));
  c.strokeStyle = color; c.beginPath(); c.arc(cx, cy, r, a0, a0 + (a1 - a0) * f); c.stroke();
  c.fillStyle = css("--text"); c.textAlign = "center";
  c.font = `bold ${Math.round(r * 0.5)}px system-ui`;
  c.fillText(label ?? fmt(value), cx, cy + r * 0.15);
}

function drawWheel(cv, deg) {
  const c = cv.getContext("2d"), w = cv.width, h = cv.height, r = w / 2 - 10;
  c.clearRect(0, 0, w, h); c.save(); c.translate(w / 2, h / 2);
  c.rotate(((num(deg) ?? 0) * Math.PI) / 180 / 3); // visual scale: steering angle / 3
  c.strokeStyle = css("--accent"); c.lineWidth = 8;
  c.beginPath(); c.arc(0, 0, r, 0, Math.PI * 2); c.stroke();
  c.lineWidth = 6; c.beginPath(); c.moveTo(-r, 0); c.lineTo(r, 0); c.moveTo(0, 0); c.lineTo(0, r); c.stroke();
  c.fillStyle = css("--accent"); c.beginPath(); c.arc(0, 0, 9, 0, 7); c.fill();
  c.fillStyle = css("--bad"); c.fillRect(-4, -r - 4, 8, 12); // top marker
  c.restore();
}

function drawSpark(cv, hist) {
  const c = cv.getContext("2d"), w = cv.width, h = cv.height;
  c.clearRect(0, 0, w, h);
  if (!hist.length) return;
  const line = (key, lo, hi, col) => {
    const pts = hist.filter((p) => num(p[key]) !== null);
    if (pts.length < 2) return;
    const t1 = hist[hist.length - 1].t;
    c.strokeStyle = col; c.lineWidth = 2; c.beginPath();
    pts.forEach((p, i) => {
      const x = w - ((t1 - p.t) / 60000) * w, y = h - 8 - ((p[key] - lo) / (hi - lo)) * (h - 16);
      i ? c.lineTo(x, y) : c.moveTo(x, y);
    });
    c.stroke();
  };
  line("coolant_c", 60, 130, css("--warn"));
  line("battery_v", 10, 15, css("--accent"));
}

function statusOf(v) {
  const seen = v.last_seen_at || S.seen[v.device_id] || S.conn[v.device_id] || S.tel[v.device_id];
  if (!seen) return "awaiting_device"; // never connected
  if (!v.profile_supported) return "profile_unsupported";
  return S.conn[v.device_id] ? "live" : "offline";
}
const statusPill = (st) => `<span class="st ${STATUS[st][1]}">${STATUS[st][0]}</span>`;

/* ---------- data ---------- */
async function loadVehicles() {
  S.vehicles = await (await fetch("/api/vehicles")).json();
  for (const v of S.vehicles) if (v.connected) { S.conn[v.device_id] = true; S.seen[v.device_id] = true; }
  if (!S.vehicles.find((v) => v.device_id === S.sel)) S.sel = S.vehicles.length ? S.vehicles[0].device_id : null;
  renderCards(); renderSelected();
}
async function loadProfiles() {
  S.profiles = await (await fetch("/api/profiles")).json();
  const opts = S.profiles.map((x) => `<option value="${esc(x.profile_id)}">${esc(x.brand)} ${esc(x.model)} (${esc(x.profile_id)})</option>`).join("")
    + '<option value="none">Not supported yet</option>';
  $("profileSel").innerHTML = opts; $("editProfileSel").innerHTML = opts;
  showProfInfo();
}
function showProfInfo() {
  const p = S.profiles.find((x) => x.profile_id === $("profileSel").value);
  $("profInfo").innerHTML = p
    ? `<b>${esc(p.description)}</b><br>Exposes: ` + p.messages.map((m) => `${esc(m.id_hex)} ${esc(m.name)} (${m.signals.map(esc).join(", ")})`).join("; ")
    : "No CAN profile: the car is registered but nothing can be decoded until a profile exists for it.";
}
async function loadAlerts() {
  const a = await (await fetch("/api/alerts?limit=40")).json();
  S.alerts = a.reverse().map((x) => ({
    device_id: x.device_id, ts: x.created_at,
    alert: { category: x.category, severity: x.severity, message: x.message, kind: (x.details || {}).kind || "mechanical" },
  }));
  renderAlerts();
}

/* ---------- rendering ---------- */
function renderCards() {
  $("cars").innerHTML = "";
  for (const v of S.vehicles) {
    const st = statusOf(v), t = S.tel[v.device_id] || {}, a = t.analysis || {}, h = a.health ? a.health.overall : null;
    const d = document.createElement("div");
    d.className = "card" + (v.device_id === S.sel ? " sel" : "");
    const scores = st === "live" || st === "offline" && t.analysis
      ? `<div class="sc"><span>Health <b style="color:${colorFor(h)}">${fmt(h)}</b></span>
         <span>Cyber <b style="color:${colorFor(a.cyber_risk, true)}">${fmt(a.cyber_risk)}</b></span></div>` : "";
    d.innerHTML = `<b>${esc(v.name)}</b>
      <small>${esc(v.brand)} ${esc(v.model)} &middot; ${esc(v.plate || "")} &middot; #${v.device_id}</small>
      ${statusPill(st)}${scores}<span class="x" title="Delete">delete</span>`;
    d.onclick = () => { S.sel = v.device_id; renderCards(); renderSelected(); renderAlerts(); };
    d.querySelector(".x").onclick = async (e) => {
      e.stopPropagation();
      if (confirm(`Delete ${v.name}? Its telemetry and alerts are removed too.`)) {
        await fetch(`/api/vehicles/${v.device_id}`, { method: "DELETE" });
        delete S.tel[v.device_id]; delete S.prov[v.device_id];
        loadVehicles();
      }
    };
    $("cars").appendChild(d);
  }
  if (!S.vehicles.length) $("cars").innerHTML = '<div class="muted">No cars registered. Use "Add car".</div>';
}

function provHtml(p, title, pfx = "pv") {
  const row = (k, v, id) => `<div class="prow"><span>${k}</span><code id="${id}">${esc(v)}</code><button type="button" class="btn sm" data-copy="${id}">Copy</button></div>`;
  return `<div class="prov"><h3>${esc(title || "Provisioning (flash these into the ESP32)")}</h3>
    ${row("Device ID", p.device_id, pfx + "_id")}${row("PSK (hex)", p.psk_hex, pfx + "_psk")}${row("Ingest URL", p.ingest_url || ingestUrl(), pfx + "_url")}
    <p class="warn-t">Shown only once. The server never returns this PSK again; if you lose it, rotate the key.</p></div>`;
}

const COMPONENTS = [["engine", "Engine"], ["thermal", "Thermal"], ["electrical", "Electrical"], ["steering_brakes", "Steering/Brakes"]];

function renderEmpty(v, st) {
  const e = $("empty");
  if (!v) { e.innerHTML = '<h2>No car selected</h2><p class="muted">Add a car to get started.</p>'; return; }
  const prov = S.prov[v.device_id];
  let body;
  if (st === "profile_unsupported") {
    body = `<p>This car's CAN profile is <code>${esc(v.can_profile)}</code>, which this server does not support. A device can connect, but its CAN frames cannot be decoded or analysed.</p>
      <p><button class="btn" data-act="edit">Assign a supported profile</button></p>`;
  } else if (st === "awaiting_device") {
    body = `<p>Registered, but no device has connected yet. Flash the ESP32 product module with the values below and power it up.</p>
      <div class="prov"><div class="prow"><span>Device ID</span><code>${v.device_id}</code></div>
      <div class="prow"><span>Ingest URL</span><code>${esc(ingestUrl())}</code></div>
      <div class="prow"><span>PSK</span><code>shown once at registration</code></div></div>`;
    if (!v.profile_supported) body += `<p class="warn-t">No supported CAN profile is assigned (${esc(v.can_profile)}). Data from the device cannot be decoded until you assign one.</p>`;
  } else {
    body = `<p>The device is offline and no telemetry has been received since the server started.</p>`;
  }
  e.innerHTML = `<h2><span>${esc(v.name)} ${statusPill(st)}</span><span><button class="btn sm" data-act="edit">Edit</button></span></h2>${body}
    <p><button class="btn sm" data-act="rotate">Rotate key</button></p>${prov ? provHtml(prov, "New provisioning (new PSK)", "pe") : ""}`;
}

function renderSelected() {
  const v = S.vehicles.find((x) => x.device_id === S.sel);
  const st = v ? statusOf(v) : null;
  const t = (v && S.tel[v.device_id]) || {};
  const hasData = v && st !== "profile_unsupported" && t.signals && t.analysis;
  $("empty").hidden = !!hasData; $("heroP").hidden = !hasData; $("liveP").hidden = !hasData;
  if (!hasData) { renderEmpty(v, st); updateInspector(t); return; }

  $("carTitle").innerHTML = `${esc(v.name)} - ${esc(v.brand)} ${esc(v.model)} ${statusPill(st)}`;
  const a = t.analysis || {}, s = t.signals || {}, hl = a.health || {};
  arcGauge($("gHealth"), hl.overall ?? 0, 100, colorFor(hl.overall), fmt(hl.overall));
  arcGauge($("gCyber"), a.cyber_risk ?? 0, 100, colorFor(a.cyber_risk, true), fmt(a.cyber_risk));
  const ac = a.attack_class || null;
  $("attack").className = "attack" + (ac && ac !== "normal" ? " hot" : "");
  $("attack").textContent = "Attack class: " + (ac ? (ATTACK_LABEL[ac] || ac) : "—") +
    (num(a.attack_confidence) !== null ? ` (${fmt(a.attack_confidence * 100)}%)` : "");
  $("bars").innerHTML = COMPONENTS.map(([k, n]) => {
    const x = num(hl[k]);
    return `<div class="row"><span>${n}</span><div class="bar"><i style="width:${x ?? 0}%;background:${colorFor(x)}"></i></div><b>${fmt(x)}</b></div>`;
  }).join("");
  $("anom").textContent = `Anomaly score: ${num(a.anomaly_score) === null ? "—" : a.anomaly_score.toFixed(2)}`;
  const fc = a.forecast || [];
  $("forecast").innerHTML = fc.length
    ? fc.map((f) => `<li class="mechanical"><b>${esc(f.signal)}</b> reaches ${esc(f.threshold)} in ~${fmt(f.eta_s)} s</li>`).join("")
    : ((s.coolant_c ?? 0) >= 110 || ((s.battery_v ?? 99) <= 11.4)
        ? '<li class="mechanical">limit already exceeded — see alerts</li>'
        : '<li class="muted">no predicted threshold crossings</li>');

  arcGauge($("gSpeed"), s.speed_kmh ?? 0, 220, css("--accent"), fmt(s.speed_kmh));
  arcGauge($("gRpm"), s.rpm ?? 0, 8000, (s.rpm ?? 0) > 6500 ? css("--bad") : css("--accent"), fmt(s.rpm));
  drawWheel($("wheel"), s.steering_deg);
  $("steerLbl").textContent = `Steering wheel ${fmt(s.steering_deg, 1)}°`;
  const bar = (n, val, d, max, unit, col, signed) => {
    const x = num(val);
    const w = x === null ? 0 : Math.min(100, (Math.abs(x) / max) * 100);
    return `<div class="m"><small>${n}</small><b>${x === null ? "—" : x.toFixed(d) + unit}</b><div class="bar"><i style="width:${w}%;background:${col}"></i></div></div>`;
  };
  const gear = num(s.gear) === null ? "—" : s.gear === 0 ? "N" : s.gear;
  $("meters").innerHTML =
    bar("Throttle", s.throttle_pct, 0, 100, " %", css("--accent")) +
    bar("Brake", s.brake_bar, 0, 150, " bar", css("--bad")) +
    `<div class="m"><small>Gear</small><b>${gear}</b></div>` +
    bar("Coolant", s.coolant_c, 0, 130, " °C", (s.coolant_c ?? 0) > 105 ? css("--bad") : css("--warn")) +
    bar("Battery", s.battery_v, 1, 15, " V", (s.battery_v ?? 12) < 11.8 ? css("--bad") : css("--ok")) +
    bar("Long. accel", s.long_accel, 2, 10, " m/s²", css("--accent")) +
    bar("Cluster speed", s.clu_speed_kmh, 0, 220, " km/h", css("--accent"));
  $("wheels").innerHTML =
    [["FL", "whl_fl_kmh"], ["FR", "whl_fr_kmh"], ["RL", "whl_rl_kmh"], ["RR", "whl_rr_kmh"]]
      .map(([n, k]) => bar(n, s[k], 0, 220, " km/h", css("--accent"))).join("");
  const mil = milActive(v.device_id);
  $("flags").innerHTML = `<span class="flag ${mil ? "on red" : ""}" title="Lit when a high/critical mechanical alert was raised in the last 10 s">MIL</span>`;
  drawSpark($("spark"), t.hist || []);
  updateInspector(t);
}

function updateInspector(t) {
  const l = (t && t.link) || {};
  $("pOk").textContent = l.packets_ok ?? 0; $("pBad").textContent = l.packets_rejected ?? 0;
  $("lnk").textContent = S.conn[S.sel] ? "link up" : "link down";
  $("cipher").textContent = l.last_cipher_hex || "—";
  $("plain").textContent = l.last_plain ? JSON.stringify(l.last_plain, null, 1) : "—";
}

function milActive(devId) {
  const now = Date.now();
  return S.alerts.some((x) => x.device_id === devId && x.alert.kind === "mechanical" &&
    (x.alert.severity === "high" || x.alert.severity === "critical") && now - Date.parse(x.ts) < 10000);
}

function renderAlerts() {
  const only = $("onlySel").checked;
  const list = S.alerts.filter((x) => !only || x.device_id === S.sel).slice(-60).reverse();
  $("alerts").innerHTML = list.map((x) => {
    const v = S.vehicles.find((q) => q.device_id === x.device_id), al = x.alert;
    const tm = new Date(x.ts).toLocaleTimeString();
    return `<li class="${esc(al.kind)} ${esc(al.severity)}"><span class="tag">${esc(al.severity)}</span><span class="tag">${esc(al.kind)}</span>${esc(al.message)}<small>${esc(v ? v.name : "device " + x.device_id)} &middot; ${esc(ALERT_LABEL[al.category] || al.category)} &middot; ${tm}</small></li>`;
  }).join("") || '<li class="muted">no alerts</li>';
}

/* ---------- voice ---------- */
function speak(devId, al) {
  if (S.muted || !("speechSynthesis" in window)) return;
  if (al.severity !== "high" && al.severity !== "critical") return;
  const now = Date.now();
  if (now - S.lastSpeak < 8000) return;
  S.lastSpeak = now;
  const v = S.vehicles.find((q) => q.device_id === devId);
  const kind = al.kind === "cyber" ? "Security alert" : "Warning";
  try { speechSynthesis.speak(new SpeechSynthesisUtterance(`${kind} for ${v ? v.name : "vehicle"}. ${al.message}`)); } catch (e) {}
}

/* ---------- live socket ---------- */
let renderPending = false;
function scheduleRender() {
  if (renderPending) return; renderPending = true;
  setTimeout(() => { renderPending = false; renderCards(); renderSelected(); }, 100);
}
function connect() {
  const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/live");
  ws.onopen = () => { $("wsState").textContent = "live"; $("wsState").className = "pill ok"; };
  ws.onclose = () => { $("wsState").textContent = "offline"; $("wsState").className = "pill bad"; setTimeout(connect, 2000); };
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data), id = m.device_id;
    if (m.type === "link") { S.conn[id] = m.connected; if (m.connected) S.seen[id] = true; scheduleRender(); }
    else if (m.type === "telemetry") {
      const t = (S.tel[id] = S.tel[id] || { hist: [] });
      t.signals = m.signals; t.analysis = m.analysis; t.link = m.link; S.conn[id] = m.link.connected; S.seen[id] = true;
      const now = Date.now();
      if (!t.hist.length || now - t.hist[t.hist.length - 1].t >= 500) {
        t.hist.push({ t: now, coolant_c: m.signals.coolant_c, battery_v: m.signals.battery_v });
        while (t.hist.length && now - t.hist[0].t > 60000) t.hist.shift();
      }
      scheduleRender();
    } else if (m.type === "alert") {
      S.alerts.push(m); if (S.alerts.length > 200) S.alerts.shift();
      renderAlerts(); speak(id, m.alert);
    }
  };
}

/* ---------- add / edit / provisioning ---------- */
const addDlg = $("addDlg"), editDlg = $("editDlg");
function openDlg(d) { if (d.showModal) d.showModal(); else d.setAttribute("open", ""); }
function closeDlg(d) { if (d.close) d.close(); else d.removeAttribute("open"); }
$("addBtn").onclick = () => {
  $("addForm").reset(); $("addMsg").textContent = ""; $("provCard").hidden = true; $("addFields").hidden = false;
  showProfInfo(); openDlg(addDlg);
};
$("addCancel").onclick = () => closeDlg(addDlg);
$("profileSel").onchange = showProfInfo;
$("addForm").onsubmit = async (e) => {
  e.preventDefault();
  if ($("provCard").hidden === false) { closeDlg(addDlg); return; }
  const body = Object.fromEntries(new FormData(e.target).entries());
  if (body.device_id === "" || body.device_id == null) delete body.device_id; else body.device_id = Number(body.device_id);
  const r = await fetch("/api/vehicles", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) { $("addMsg").textContent = "Error: " + (typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail)); return; }
  S.sel = j.device_id;
  $("addFields").hidden = true; $("provCard").hidden = false;
  $("provCard").innerHTML = `<p>Car registered as <b>${esc(j.name)}</b> (${esc(j.status)}).</p>${provHtml(j.provisioning, undefined, "pa")}
    <div class="dlgbtns"><button class="btn primary" type="submit">Done</button></div>`;
  loadVehicles();
};
$("editCancel").onclick = () => closeDlg(editDlg);
$("editForm").onsubmit = async (e) => {
  e.preventDefault();
  const body = Object.fromEntries(new FormData(e.target).entries());
  const r = await fetch(`/api/vehicles/${S.sel}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) { const j = await r.json(); $("editMsg").textContent = "Error: " + (typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail)); return; }
  closeDlg(editDlg);
  delete S.tel[S.sel]; // decoded signals depend on the profile
  loadVehicles();
};
function openEdit() {
  const v = S.vehicles.find((x) => x.device_id === S.sel); if (!v) return;
  const f = $("editForm"); f.name.value = v.name; f.plate.value = v.plate;
  const known = S.profiles.some((p) => p.profile_id === v.can_profile);
  f.can_profile.value = known ? v.can_profile : "none"; $("editMsg").textContent = "";
  openDlg(editDlg);
}
$("editBtn").onclick = openEdit;

document.addEventListener("click", async (e) => {
  const cp = e.target.closest("[data-copy]");
  if (cp) {
    const txt = $(cp.dataset.copy).textContent;
    try { await navigator.clipboard.writeText(txt); cp.textContent = "Copied"; }
    catch (err) { // clipboard API needs a secure context; fall back to selection
      const r = document.createRange(); r.selectNodeContents($(cp.dataset.copy));
      const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); cp.textContent = "Selected";
    }
    setTimeout(() => (cp.textContent = "Copy"), 1500);
    return;
  }
  const act = e.target.closest("[data-act]");
  if (!act) return;
  if (act.dataset.act === "edit") openEdit();
  if (act.dataset.act === "rotate" && confirm("Rotate the key? The old PSK stops working at the next handshake.")) {
    const r = await fetch(`/api/vehicles/${S.sel}/rotate-key`, { method: "POST" });
    if (r.ok) { S.prov[S.sel] = await r.json(); renderSelected(); }
  }
});

/* ---------- init ---------- */
$("muteBtn").onclick = () => {
  S.muted = !S.muted; $("muteBtn").textContent = "Voice: " + (S.muted ? "muted" : "on");
  if (S.muted && "speechSynthesis" in window) speechSynthesis.cancel();
};
$("onlySel").onchange = renderAlerts;
setInterval(() => { if (S.sel !== null && !$("liveP").hidden) renderSelected(); }, 1000); // lets the MIL lamp expire after 10 s
loadProfiles(); loadVehicles().then(loadAlerts); connect();

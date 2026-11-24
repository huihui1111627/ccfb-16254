let state = null;
let selectedUser = 1;
let selectedMigration = null;
let packetMode = "cid";
let packetTrace = null;
let packetLabel = "";
let heatMode = "cid";
let heatMetric = "packets";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));
const fmtT = (t) => {
  if (t === null || t === undefined || t === "") return "—";
  const s = Number(t) / 1000;
  if (s < 60) return s.toFixed(1) + "s";
  const m = Math.floor(s / 60);
  return `${m}:${(s - m * 60).toFixed(1).padStart(4, "0")}`;
};
const pct = (a, b) => b ? (100 * a / b).toFixed(1) + "%" : "—";
const clamp = (x, a, b) => Math.max(a, Math.min(b, x));

async function loadState() {
  const res = await fetch("/api/state");
  const data = await res.json();
  state = data.report;
  $("runStatus").textContent = "模拟完成 · 种子 " + state.config.seed;
  renderAll();
}

function renderAll() {
  if (!state) return;
  const firstInteresting = state.migrations.find(m => !m.old.preserved && m.lbChanged) || state.migrations[0];
  if (!selectedMigration || !state.migrations.find(m => m.id === selectedMigration)) {
    selectedMigration = firstInteresting?.id;
  }
  if (!state.users.find(u => u.n === selectedUser)) selectedUser = state.users[0]?.n;
  if (!packetTrace) {
    const m = currentMigration();
    packetTrace = m?.sessionId || state.cid.connections[0]?.id;
    packetLabel = packetTrace || "";
  }
  renderKPIs();
  renderUserList();
  renderUserDetail();
  renderOps();
  renderLoad();
  renderSecurity();
  renderProtocol();
  renderCompare();
  loadPackets();
}

function currentMigration() {
  return state.migrations.find(m => m.id === selectedMigration);
}
function userMigrations(n) {
  return state.migrations.filter(m => m.user === n).sort((a,b) => a.t-b.t);
}
function migMap() {
  return Object.fromEntries(state.migrations.map(m => [m.id, m]));
}

function renderKPIs() {
  const c = state.cid.stats, o = state.old.stats;
  const cards = [
    ["good", "地址切换后保活", `${c.preserved}/${c.migrations}`, `CID 保活 ${pct(c.preserved,c.migrations)}；老哈希仅 ${o.preserved}/${o.migrations}`],
    [o.misrouted ? "bad" : "good", "被错误路由的包", c.misrouted, `老地址哈希 ${o.misrouted.toLocaleString()} 包，另有 ${o.resetPackets} 个无状态重置`],
    ["warn", "重新握手 / 卡顿", "0", `老路径 ${o.rehandshakes} 次，模拟累计卡顿 ${(o.totalStallMs/1000).toFixed(0)}s`],
    ["bad", "上传失败包", c.uploadFailed, `老路径 ${o.uploadFailed}/${o.uploads} 个上传包失败`],
    ["info", "后端负载 CV / Jain", c.backendCv.toFixed(2), `CID Jain ${c.jainFairness.toFixed(3)}；老路径 CV ${o.backendCv.toFixed(2)} / Jain ${o.jainFairness.toFixed(3)}`],
    ["good", "伪造 CID 拦截", `${state.security.forgedRejected}/${state.security.forgedTotal}`, `跨 LB 路由分歧 ${c.lbDisagreements}；切网 ECMP 变化 ${state.migrations.filter(m=>m.lbChanged).length} 次；重启丢包 ${c.lbRestartDrops}`]
  ];
  $("kpis").innerHTML = cards.map(([tone,label,value,sub]) => `
    <div class="kpi ${tone}">
      <div class="label">${label}</div>
      <div class="value ${tone}-text">${value}</div>
      <div class="sub">${sub}</div>
    </div>`).join("");
}

function renderUserList() {
  $("userList").innerHTML = state.users.map(u => {
    const ms = userMigrations(u.n);
    const bad = ms.filter(m => !m.old.preserved).length;
    const active = u.n === selectedUser ? "active" : "";
    const dots = ms.slice(0, 14).map(m => `<i class="mini-dot ${m.old.preserved ? "" : "bad"}"></i>`).join("");
    return `
      <button class="user-btn ${active}" onclick="selectUser(${u.n})">
        <div class="user-row1"><span>${u.id}</span><span class="badge info">${u.startNet}</span></div>
        <div class="user-meta"><span>${ms.length} 次切网 · ${u.sessionIds.length} 个 CID 连接</span><span class="${bad ? "bad-text" : "good-text"}">${bad ? bad + " 次老路径断连" : "老路径全幸存"}</span></div>
        <div class="mini-dots">${dots}</div>
      </button>`;
  }).join("");
}

window.selectUser = (n) => {
  selectedUser = n;
  const ms = userMigrations(n);
  selectedMigration = (ms.find(m => !m.old.preserved && m.lbChanged) || ms[0])?.id || null;
  packetTrace = currentMigration()?.sessionId || state.cid.connections.find(c=>c.user===n)?.id;
  packetLabel = packetTrace || "";
  renderUserList();
  renderUserDetail();
  loadPackets();
};

window.selectMigration = (id) => {
  selectedMigration = id;
  const m = currentMigration();
  if (m?.sessionId) {
    packetTrace = m.sessionId;
    packetLabel = m.sessionId;
    loadPackets();
  }
  renderUserDetail();
};

window.selectPacket = (mode, trace) => {
  packetMode = mode;
  packetTrace = (trace || "").split("#")[0];
  packetLabel = trace || packetTrace;
  const related = state.migrations
    .filter(m => m.sessionId === packetTrace)
    .sort((a, b) => a.t - b.t);
  if (related.length && !related.some(m => m.id === selectedMigration)) {
    selectedMigration = related[0].id;
    renderUserDetail();
  }
  document.querySelectorAll("[data-pmode]").forEach(b => b.classList.toggle("active", b.dataset.pmode === mode));
  loadPackets();
};

function renderUserDetail() {
  const u = state.users.find(x => x.n === selectedUser);
  if (!u) return;
  const ms = userMigrations(u.n);
  const cidBad = ms.filter(m => !m.cid.preserved).length;
  const oldBad = ms.filter(m => !m.old.preserved).length;
  $("userSummary").innerHTML = `
    <span class="summary-pill">用户 <b>${u.id}</b></span>
    <span class="summary-pill">初始网络 <b>${esc(u.startNet)} · ${esc(u.initialAddr.ip)}:${u.initialAddr.port}</b></span>
    <span class="summary-pill">切网 <b>${ms.length}</b> 次</span>
    <span class="summary-pill">CID 断连 <b class="${cidBad ? "bad-text" : "good-text"}">${cidBad}</b></span>
    <span class="summary-pill">老哈希断连 <b class="${oldBad ? "bad-text" : "bad-text"}">${oldBad}</b></span>`;

  $("migrationChips").innerHTML = ms.map(m => `
    <button class="chip ${m.id===selectedMigration?"active":""}" onclick="selectMigration('${m.id}')">
      ${fmtT(m.t)} ${esc(m.from.network)}→${esc(m.to.network)}
      ${m.old.preserved ? "" : '<span class="bad-text">●</span>'}
    </button>`).join("");

  renderMigrationDetail();
  renderTrajectory();
  renderSwimlanes();
}

function addrCard(title, a) {
  return `<div class="addr-card">
    <div class="net">${title} · ${esc(a.network)}</div>
    <div class="addr">${esc(a.ip)}<span class="port">:${a.port}</span></div>
  </div>`;
}

function resultCard(title, r, mode) {
  const ok = r.preserved;
  return `<div class="result-card">
    <h4>${title} <span class="badge ${ok ? "good" : "bad"}">${ok ? "连接保住" : "需要重握手"}</span></h4>
    <dl class="kv">
      <dt>后端轨迹</dt><dd>${esc(r.beforeBackend)} → ${esc(r.afterBackend)}</dd>
      <dt>错路包</dt><dd class="${r.wrong ? "bad-text" : "good-text"}">${r.wrong}</dd>
      <dt>卡顿</dt><dd>${r.stallMs ? (r.stallMs/1000).toFixed(1)+"s" : "0"}</dd>
      <dt>上传</dt><dd>${r.uploadFailed ? '<span class="bad-text">失败</span>' : '<span class="good-text">正常/无</span>'}</dd>
    </dl>
  </div>`;
}

function renderMigrationDetail() {
  const m = currentMigration();
  if (!m) {
    $("migrationDetail").innerHTML = `<div class="addr-card">该用户没有网络切换事件。</div>`;
    return;
  }
  const lbCard = `<div class="result-card">
    <h4>ECMP / LB 实例 <span class="badge ${m.lbChanged ? "warn" : "info"}">${m.lbChanged ? "LB 实例变化" : "同一 LB"}</span></h4>
    <dl class="kv">
      <dt>切换前</dt><dd>${esc(m.lbBefore || "—")}</dd>
      <dt>切换后</dt><dd>${esc(m.lbAfter || "—")}</dd>
      <dt>共享状态</dt><dd>无连接表</dd>
      <dt>一致性</dt><dd class="good-text">同一 CID → 同一后端</dd>
      <dt>连接 trace</dt><dd class="mono">${esc(m.sessionId || "—")}</dd>
    </dl>
  </div>`;
  $("migrationDetail").innerHTML =
    addrCard("旧地址", m.from) +
    addrCard("新地址", m.to) +
    lbCard +
    resultCard("CID 路由", m.cid, "cid") +
    resultCard("源地址哈希", m.old, "old");
}

function renderTrajectory() {
  const u = state.users.find(x => x.n === selectedUser);
  $("trajectoryUser").textContent = `${u?.id || ""} 的外层地址与落点变化`;
  const mm = migMap();
  const items = userMigrations(selectedUser);
  $("trajectory").innerHTML = items.map(sw => {
    const m = mm[sw.id];
    return `<div class="traj-item">
      <div class="traj-time">${fmtT(sw.t)}</div>
      <div class="traj-dot"></div>
      <div class="traj-body">
        <div><span class="badge info">${esc(sw.from.network)}</span> <span class="route">${esc(sw.from.ip)}:${sw.from.port}</span></div>
        <div class="route">↓ ${esc(sw.reason)}</div>
        <div><span class="badge ${sw.to.network==="Wi-Fi"?"good":"warn"}">${esc(sw.to.network)}</span> <span class="route">${esc(sw.to.ip)}:${sw.to.port}</span></div>
        ${m ? `<p>${m.sessionId === packetTrace ? '<span class="badge info">当前包表连接</span> ' : ""}CID：${esc(m.cid.afterBackend)} · 错路 ${m.cid.wrong}；老哈希：${esc(m.old.afterBackend)} · 错路 ${m.old.wrong} · ${m.old.rehandshake ? "重握手" : "未断"}</p>` : ""}
      </div>
    </div>`;
  }).join("");
}

function renderSwimlanes() {
  $("swimlanes").innerHTML = swimlane("cid") + swimlane("old");
}

function swimlane(mode) {
  const W = 1040, L = 58, R = 18, T = 30, rowH = 34;
  const backs = state.backends.map(b => b.id).sort((a,b) => Number(a.slice(2))-Number(b.slice(2)));
  const H = T + backs.length * rowH + 28;
  const dur = state.config.durationMs;
  const x = t => L + clamp(t / dur, 0, 1) * (W-L-R);
  const y = id => T + backs.indexOf(id) * rowH;
  const userSwitches = userMigrations(selectedUser);
  const conns = state[mode].connections.filter(c => c.user === selectedUser);

  const grid = backs.map((id, i) => `
    <line x1="${L}" x2="${W-R}" y1="${y(id)+22}" y2="${y(id)+22}" stroke="#1d2a48" stroke-width="1"/>
    <text class="lane-label" x="10" y="${y(id)+17}">${id}</text>`).join("");

  const timeTicks = [0,.25,.5,.75,1].map(f => {
    const xx = L + f*(W-L-R);
    return `<text class="axis-label" x="${xx-14}" y="${H-7}">${fmtT(f*dur)}</text>`;
  }).join("");

  const ops = state.ops.map(op => {
    const cls = op.kind.startsWith("backend") ? "op-line-scale" : "op-line-" + op.kind;
    return `<line class="${cls}" x1="${x(op.t)}" x2="${x(op.t)}" y1="18" y2="${H-24}">
      <title>${fmtT(op.t)} ${esc(op.title)}&#10;${esc(op.detail || "")}</title></line>`;
  }).join("");

  const swLines = userSwitches.map(m => `
    <line class="switch-line" x1="${x(m.t)}" x2="${x(m.t)}" y1="18" y2="${H-24}">
      <title>${fmtT(m.t)} ${esc(m.from.network)} → ${esc(m.to.network)}</title></line>`).join("");

  const rects = conns.map(c => {
    const xx = x(c.startT), ww = Math.max(3, x(c.endT)-xx);
    let fill, stroke, cls = "rect-conn";
    if (mode === "cid") {
      fill = "rgba(52,211,153,.72)"; stroke = "#34d399";
    } else if (c.wrong > 0 || c.rehandshake) {
      fill = "rgba(251,113,133,.72)"; stroke = "#fb7185";
    } else {
      fill = "rgba(96,165,250,.62)"; stroke = "#60a5fa";
    }
    const trace = mode === "cid" ? c.id : (c.parentId || c.id);
    const label = `${c.id}\n后端 ${c.owner}\n${fmtT(c.startT)}–${fmtT(c.endT)}\n包 ${c.packets}，错路 ${c.wrong}`;
    return `<rect class="${cls}" x="${xx}" y="${y(c.owner)+5}" width="${ww}" height="20" rx="6"
      fill="${fill}" stroke="${stroke}" onclick="selectPacket('${mode}','${trace}')"><title>${esc(label)}</title></rect>`;
  }).join("");

  const title = mode === "cid"
    ? "CID 路由：会话条应始终停在同一后端行"
    : "源地址哈希：切网后常见红色断裂，并在新后端行产生新的握手代数";
  return `<div class="swim-panel">
    <h4><span>${title}</span><span>${conns.length} 条${mode === "cid" ? "连接" : "连接代数"}</span></h4>
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${title}">
      ${grid}${ops}${swLines}${rects}${timeTicks}
    </svg>
  </div>`;
}

document.querySelectorAll("[data-pmode]").forEach(btn => {
  btn.addEventListener("click", () => {
    packetMode = btn.dataset.pmode;
    document.querySelectorAll("[data-pmode]").forEach(b => b.classList.toggle("active", b === btn));
    loadPackets();
  });
});

async function loadPackets() {
  document.querySelectorAll("[data-pmode]").forEach(b => b.classList.toggle("active", b.dataset.pmode === packetMode));
  if (!packetTrace) {
    $("packetRows").innerHTML = "";
    return;
  }
  $("packetTraceName").textContent = `${packetMode.toUpperCase()} · ${packetLabel || packetTrace}`;
  try {
    const res = await fetch(`/api/packets?mode=${packetMode}&trace=${encodeURIComponent(packetTrace)}`);
    const data = await res.json();
    renderPackets(data.packets || []);
  } catch (e) {
    $("packetRows").innerHTML = `<tr><td colspan="7">加载失败：${esc(e)}</td></tr>`;
  }
}

function renderPackets(packets) {
  const rows = packets.slice().sort((a,b) => a.t-b.t || a.seq-b.seq).map(r => {
    const classes = [];
    if (r.lost) classes.push("lost");
    if (r.reordered) classes.push("reorder");
    if (r.kind === "stateless_reset") classes.push("reset");
    let status;
    if (r.lost) status = `<span class="status-tag muted">网络丢包</span>`;
    else if (r.kind === "stateless_reset") status = `<span class="status-tag err">无状态重置</span>`;
    else if (!r.routed) status = `<span class="status-tag err">LB 丢弃</span>`;
    else if (r.correct) status = `<span class="status-tag ok">正确</span>`;
    else status = `<span class="status-tag err">错误路由</span>`;
    const src = r.src?.network ? `${esc(r.src.network)}<br><span class="mono">${esc(r.src.ip)}:${r.src.port}</span>` : "—";
    return `<tr class="${classes.join(" ")}">
      <td class="mono">${(r.t/1000).toFixed(2)}s</td>
      <td><span class="badge info">${esc(r.header || r.kind)}</span><br><small class="muted">seq ${r.seq}</small></td>
      <td>${src}</td>
      <td class="mono">${esc(r.lb || "—")}</td>
      <td class="mono">${esc(r.expected || "—")} → <b class="${r.correct ? "good-text" : "bad-text"}">${esc(r.routed || "×")}</b></td>
      <td>${status}</td>
      <td>${esc(r.detail || "")}</td>
    </tr>`;
  }).join("");
  $("packetRows").innerHTML = rows || `<tr><td colspan="7">该 trace 没有包记录。</td></tr>`;
}

function renderOps() {
  $("lbFleet").innerHTML = state.lbs.map(lb => {
    const cls = ["lb-chip"];
    if (lb.restarts?.length) cls.push("restart");
    if (lb.removedT) cls.push("removed");
    const status = lb.removedT
      ? `${fmtT(lb.addedT)} 加入 · ${fmtT(lb.removedT)} 摘除`
      : `${fmtT(lb.addedT)} 加入 · ECMP 成员`;
    const restart = lb.restarts?.length ? ` · 重启 ${lb.restarts.length} 次` : "";
    return `<div class="${cls.join(" ")}" title="LB 不保存连接表；任何实例都能用共享密钥解析 CID">
      <b>${esc(lb.id)}</b><span>${status}${restart}</span>
    </div>`;
  }).join("");
  $("opsTimeline").innerHTML = state.ops.map(op => `
    <div class="op-item ${esc(op.tone || "info")}">
      <div class="op-time">${fmtT(op.t)}</div>
      <div class="op-node"></div>
      <div class="op-body"><h4>${esc(op.title)}</h4><p>${esc(op.detail || "")}</p></div>
    </div>`).join("");
}

function renderLoad() {
  const max = Math.max(1, ...state.backends.map(b => Math.max(b.cidPackets, b.oldPackets)));
  $("loadBars").innerHTML = state.backends.map(b => `
    <div class="load-row">
      <div class="mono">${b.id}</div>
      <div class="dual-bars">
        <div class="bar-line"><div class="load-fill cid" style="width:${100*b.cidPackets/max}%"></div></div>
        <div class="bar-line"><div class="load-fill old" style="width:${100*b.oldPackets/max}%"></div></div>
      </div>
      <div class="load-nums">CID ${b.cidPackets} (${(b.cidShare*100).toFixed(1)}%)<br>老 ${b.oldPackets} (${(b.oldShare*100).toFixed(1)}%)</div>
    </div>`).join("");
  renderHeatmap();
}

function renderHeatmap() {
  const key = heatMetric === "conn" ? heatMode + "Conns" : heatMode;
  let max = 1;
  state.loadSeries.forEach(p => state.backends.forEach(b => { max = Math.max(max, p[key]?.[b.id] || 0); }));
  const color = heatMetric === "conn"
    ? (v) => `rgba(167,139,250,${0.10 + .82*v/max})`
    : heatMode === "cid"
      ? (v) => `rgba(52,211,153,${0.08 + .82*v/max})`
      : (v) => `rgba(251,113,133,${0.08 + .82*v/max})`;
  let html = "";
  const heatmap = $("heatmap");
  heatmap.style.gridTemplateColumns = `52px repeat(${state.loadSeries.length}, minmax(7px, 1fr))`;
  state.backends.forEach(b => {
    html += `<div class="heat-label">${b.id}</div>`;
    state.loadSeries.forEach(p => {
      const v = p[key]?.[b.id] || 0;
      html += `<div class="heat-cell" style="background:${color(v)}" title="${fmtT(p.t)} ${b.id} · ${v}"></div>`;
    });
  });
  $("heatmap").innerHTML = html;
  const durationSec = state.config.durationMs / 1000;
  $("heatAxis").innerHTML = Array.from({ length: 9 }, (_, i) => {
    const t = Math.round(durationSec * i / 8);
    return `<span>${t}s</span>`;
  }).join("");
  $("heatCid").classList.toggle("active", heatMode === "cid");
  $("heatOld").classList.toggle("active", heatMode === "old");
  $("heatMetric").textContent = heatMetric === "packets" ? "指标：包量" : "指标：连接数";
  $("heatMetric").classList.toggle("active", heatMetric === "conn");
}
$("heatCid")?.addEventListener("click", () => { heatMode="cid"; renderHeatmap(); });
$("heatOld")?.addEventListener("click", () => { heatMode="old"; renderHeatmap(); });
$("heatMetric")?.addEventListener("click", () => { heatMetric = heatMetric==="packets" ? "conn" : "packets"; renderHeatmap(); });

function renderSecurity() {
  const s = state.security;
  $("cidSecurity").innerHTML = `
    <div class="cid-format">
      <div class="cid-seg kid"><b>keyID</b><span>1B 密钥代次</span></div>
      <div class="cid-seg nonce"><b>nonce</b><span>7B 随机盐</span></div>
      <div class="cid-seg id"><b>backend ID</b><span>4B AES-CTR 密文</span></div>
      <div class="cid-seg mac"><b>MAC</b><span>8B HMAC 截断</span></div>
    </div>
    <p class="panel-head p" style="color:var(--muted);font-size:12px;line-height:1.6;margin:0 0 10px">
      线上 20 字节 CID 无后端明文字段；下面的后端列是演练台的“共享密钥持有者视角”。同一后端的两个 CID 因 nonce 不同而完全不同。
      算法：${esc(s.algorithm)}；错误密钥生成的 CID 也会被拒绝：<b class="good-text">${s.wrongKeyReject ? "是" : "否"}</b>。
    </p>
    <div class="security-grid">
      <div class="security-stat"><b class="bad-text">${s.forgedTotal}</b><span>伪造/猜测 CID 测试</span></div>
      <div class="security-stat"><b class="good-text">${s.forgedRejected}</b><span>MAC 验证拒绝</span></div>
      <div class="security-stat"><b>${s.agreedLength}B</b><span>约定短 CID 长度</span></div>
    </div>
    <div class="cid-examples">
      ${state.cidExamples.map(e => `<div class="cid-example"><span class="badge good">${e.backend}</span><code>${esc(e.cid)}</code></div>`).join("")}
    </div>`;
}

function renderProtocol() {
  const c = state.cid.stats, o = state.old.stats;
  const cards = [
    ["长包头", "首字节 Header Form=1；随后 32 位版本、DCID Length、DCID、SCID Length、SCID。Initial / Handshake / 0-RTT 按类型位区分。", `本模拟长包头记录：${c.longPackets}`],
    ["短包头 / 1-RTT", "首字节 Header Form=0；没有 DCID 长度字段，LB 按部署约定固定读取 20 字节并验 MAC。", `短包头记录：${c.shortPackets}`],
    ["版本协商", "Version Negotiation 的 Version=0，随后是 DCID/SCID 和支持版本列表；不创建连接状态，单独计数。", `VN 样本：${c.vnPackets}`],
    ["无状态重置", "Reset 没有独立类型；接收方检查整个包末尾 16 字节 reset token。老哈希把包打到陌生后端时触发。", `老路径 reset：${o.resetPackets}`]
  ];
  $("protocolCards").innerHTML = cards.map(([h,p,code]) => `
    <div class="proto-card"><h4>${h}</h4><p>${p}</p><code>${code}</code></div>`).join("");
}

function renderCompare() {
  const c = state.cid.stats, o = state.old.stats;
  const rows = [
    ["切网后连接保活", `${c.preserved}/${c.migrations}（${pct(c.preserved,c.migrations)}）`, `${o.preserved}/${o.migrations}（${pct(o.preserved,o.migrations)}）`, "CID 由连接 ID 固定后端；地址哈希键完全改变。"],
    ["错误路由包", c.misrouted.toLocaleString(), o.misrouted.toLocaleString(), "到达了不拥有该 QUIC 连接的后端。"],
    ["重新握手", c.rehandshakes, o.rehandshakes, "老路径陌生后端只能重置，客户端重建 QUIC 连接。"],
    ["模拟卡顿", "0s", `${(o.totalStallMs/1000).toFixed(1)}s`, "每次重握手计入约 1.2s 的视频卡顿/请求超时窗口。"],
    ["上传失败包", c.uploadFailed, o.uploadFailed, "切网后立即发出的一次性上传最容易直接失败。"],
    ["网络丢包 / 乱序", `${c.lost} / ${c.reordered}`, `${o.lost} / ${o.reordered}`, "两种模式使用完全相同的丢包、延迟和乱序输入。"],
    ["负载 CV（越低越均匀）", c.backendCv.toFixed(3), o.backendCv.toFixed(3), "按后端在线时长归一化的包量变异系数。"],
    ["Jain 公平性（越高越均匀）", c.jainFairness.toFixed(4), o.jainFairness.toFixed(4), "1 表示所有后端速率完全相同。"],
    ["伪造 CID", `${state.security.forgedRejected}/${state.security.forgedTotal} 拒绝`, "不校验 CID，按地址转发", "HMAC 先验证，攻击者不能把身份改成指定后端。"],
    ["LB 共享状态", `无连接表；跨实例分歧 ${c.lbDisagreements}`, "无状态但键随地址变化", "ECMP 换到任何 LB 实例，CID 路由结论一致。"]
  ];
  $("compareRows").innerHTML = rows.map(r => `
    <tr><td>${r[0]}</td><td class="good-text">${r[1]}</td><td class="bad-text">${r[2]}</td><td style="color:var(--muted)">${r[3]}</td></tr>`).join("");
}

$("rerun")?.addEventListener("click", async () => {
  $("runStatus").textContent = "重新模拟中…";
  const users = $("userCount").value || 64;
  const seed = $("seed").value || 1;
  await fetch(`/api/rerun?users=${encodeURIComponent(users)}&seed=${encodeURIComponent(seed)}`, { method: "POST" });
  packetTrace = null;
  selectedMigration = null;
  await loadState();
});

loadState().catch(err => {
  $("runStatus").textContent = "加载失败";
  $("kpis").innerHTML = `<div class="kpi bad"><div class="label">无法读取 /api/state</div><div class="sub">${esc(err)}</div></div>`;
});

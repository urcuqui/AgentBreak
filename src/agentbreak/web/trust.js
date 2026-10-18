// Agent Trust Lab frontend. Plain JS, no framework.
// Renders results from the same core the CLI uses; it never decides an outcome.

const $ = (id) => document.getElementById(id);

const BASELINE = "baseline";
const BROADENED = "broadened-incident-access";
const BASELINE_TOOLS = ["search_knowledge_base"];
const CONTROLS = [
  "tool_authorization", "argument_validation", "data_classification",
  "approval_gate", "egress_control",
];
const RESULT_TONE = {
  NO_ATTACK: "info", ATTACK_SUCCESS: "danger",
  PARTIALLY_MITIGATED: "warn", ATTACK_BLOCKED: "safe",
};
const RESULT_ICON = { NO_ATTACK: "●", ATTACK_SUCCESS: "✗", PARTIALLY_MITIGATED: "⚠", ATTACK_BLOCKED: "✓" };

const STEPS = [
  ["normal", "Normal"], ["attack", "Attack"], ["evidence", "Evidence"],
  ["test", "Create test"], ["regression", "Regression"], ["fix", "Fix"],
  ["verify", "Verify"], ["gate", "CI gate"],
];

const state = {
  profile: BASELINE,
  profiles: [],
  cases: [],
  runs: {},          // last run per mode
  lastRun: null,
  created: null,
  suite: null,
  flow: {},          // step -> true once done
  busy: false,
};

// --- helpers --------------------------------------------------------------
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

function badge(text, tone, icon) {
  return el("span", `badge-lg b-${tone}`, icon ? `${icon} ${text}` : text);
}

function resultBadge(result) {
  return badge(result, RESULT_TONE[result] || "info", RESULT_ICON[result]);
}

function yesNo(flag, toneYes) {
  return flag ? badge("YES", toneYes, toneYes === "danger" ? "✗" : "⚠") : badge("NO", "safe", "✓");
}

function kv(rows) {
  const dl = el("dl", "kv");
  rows.forEach(([k, v]) => {
    dl.appendChild(el("dt", null, k));
    const dd = el("dd");
    if (v instanceof Node) dd.appendChild(v); else dd.textContent = v ?? "—";
    dl.appendChild(dd);
  });
  return dl;
}

function toolList(names, tone) {
  const ul = el("ul", "tool-list");
  if (!names || !names.length) { ul.appendChild(el("li", "muted", "none")); return ul; }
  names.forEach((n) => ul.appendChild(el("li", `tool t-${tone(n)}`, n)));
  return ul;
}

function shortHash(h) { return h ? `${h.slice(0, 12)}…` : "—"; }

async function api(method, url, body) {
  const r = await fetch(url, {
    method, headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `${r.status} ${r.statusText}`);
  return data;
}

// Highlight the injected phrases (the core's suspicious-content signal) in the payload.
function highlightPayload(text, findings) {
  const pre = el("pre", "payload");
  const patterns = (findings || []).map((f) => f.pattern.toLowerCase());
  const lower = text.toLowerCase();
  let i = 0;
  while (i < text.length) {
    let next = -1, len = 0;
    patterns.forEach((p) => {
      const idx = lower.indexOf(p, i);
      if (idx !== -1 && (next === -1 || idx < next)) { next = idx; len = p.length; }
    });
    if (next === -1) { pre.appendChild(document.createTextNode(text.slice(i))); break; }
    pre.appendChild(document.createTextNode(text.slice(i, next)));
    pre.appendChild(el("mark", null, text.slice(next, next + len)));
    i = next + len;
  }
  return pre;
}

// --- execution view -------------------------------------------------------
function setNode(name, tone, label) {
  const li = document.querySelector(`#chain li[data-node="${name}"]`);
  li.className = `n-${tone}`;
  li.querySelector(".node-state").textContent = label;
}

function renderRun(run) {
  const requested = run.tool_calls.map((c) => c.tool);
  const privileged = requested.filter((t) => !BASELINE_TOOLS.includes(t));
  const injected = (run.evidence.suspicious_findings || []).length > 0;
  const anyBlocked = run.tool_calls.some((c) => c.outcome === "BLOCKED");

  $("run-label").textContent =
    `${run.run_id} · mode=${run.mode} · posture=${run.policy_enabled ? run.control_profile : "policy layer OFF"}`;

  // Chain
  setNode("context", injected ? "warn" : "info", injected ? "⚠ injected instructions" : "● benign");
  setNode("agent", run.agent_influenced ? "warn" : "info", run.agent_influenced ? "⚠ influenced" : "● on task");
  setNode("proposal", privileged.length ? "warn" : "info",
    privileged.length ? `⚠ ${privileged.join(", ")}` : "● search_knowledge_base");
  if (!run.policy_enabled) setNode("policy", "danger", "✗ disabled");
  else if (run.boundary_crossed) setNode("policy", "warn", "⚠ enforced, but a privileged call passed");
  else setNode("policy", "safe", anyBlocked ? "✓ enforced (blocked)" : "✓ enforced (allowed)");
  setNode("runtime", run.boundary_crossed ? "danger" : "safe",
    run.boundary_crossed ? "✗ boundary crossed" : "✓ no impact");

  // Context column
  const ctx = $("ctx-body");
  ctx.className = "";
  ctx.replaceChildren(
    kv([
      ["Source", run.context_source],
      ["Document", run.document ? run.document.title : "—"],
      ["Trust", badge((run.trust_level || "").toUpperCase(), "warn", "⚠")],
      ["Payload sha256", el("code", null, shortHash(run.payload_sha256))],
    ]),
    highlightPayload(run.payload || "", run.evidence.suspicious_findings),
  );
  // Bring the injected block into view inside the payload box.
  const firstMark = ctx.querySelector(".payload mark");
  if (firstMark) firstMark.parentNode.scrollTop = Math.max(0, firstMark.offsetTop - firstMark.parentNode.offsetTop - 40);
  if (injected) {
    ctx.appendChild(el("p", "muted small",
      "Highlighted: injection signal from detect_suspicious_content(). A signal only, never the gate."));
  }

  // Agent column
  const agent = $("agent-body");
  agent.className = "";
  agent.replaceChildren(kv([["User task", run.user_input]]), el("p", "sub", "Requested tools"));
  const ul = el("ul", "calls");
  run.tool_calls.forEach((c) => {
    const li = el("li", BASELINE_TOOLS.includes(c.tool) ? "call t-info" : "call t-warn");
    li.appendChild(el("strong", null, `${BASELINE_TOOLS.includes(c.tool) ? "●" : "⚠"} ${c.tool}`));
    li.appendChild(el("code", "args", JSON.stringify(c.arguments)));
    li.appendChild(el("span", "muted small", c.reason));
    ul.appendChild(li);
  });
  agent.appendChild(ul);

  // Boundary column
  const b = $("boundary-body");
  b.className = "";
  b.replaceChildren(kv([
    ["Policy layer", run.policy_enabled ? badge("ENFORCED", "safe", "🛡") : badge("DISABLED", "danger", "✗")],
  ]));
  const calls = el("ul", "calls");
  run.tool_calls.forEach((c) => {
    const executed = c.outcome === "EXECUTED";
    const tone = executed ? (BASELINE_TOOLS.includes(c.tool) ? "info" : "danger") : "safe";
    const li = el("li", `call t-${tone}`);
    li.appendChild(el("strong", null, `${executed ? (tone === "danger" ? "✗" : "●") : "✓"} ${c.tool}`));
    li.appendChild(el("span", "small", executed ? "EXECUTED" : "BLOCKED by policy"));
    calls.appendChild(li);
  });
  b.appendChild(calls);
  b.appendChild(kv([["Security impact", run.security_impact]]));

  // Verdict
  $("verdict").hidden = false;
  const vi = $("v-influenced");
  vi.replaceChildren(el("span", "eyebrow", "Agent influenced"), yesNo(run.agent_influenced, "warn"));
  const vb = $("v-boundary");
  vb.replaceChildren(el("span", "eyebrow", "Boundary crossed"), yesNo(run.boundary_crossed, "danger"));
  $("v-result").replaceChildren(el("span", "eyebrow", "Final result"), resultBadge(run.final_result));

  renderPolicy(run);
  renderEvidence(run);
}

function renderPolicy(run) {
  $("policy-wrap").hidden = false;
  const box = $("policy-matrix");
  if (!run.policy_enabled) {
    box.replaceChildren(el("p", "callout c-danger",
      "✗ Policy layer disabled in attack mode (the vulnerable path): every proposed tool call executed unconditionally. No control was evaluated."));
    return;
  }
  const table = el("table", "matrix");
  const head = el("tr");
  head.appendChild(el("th", null, "Tool"));
  CONTROLS.forEach((c) => head.appendChild(el("th", null, c)));
  head.appendChild(el("th", null, "Outcome"));
  table.appendChild(el("thead")).appendChild(head);
  const body = el("tbody");
  run.tool_calls.forEach((c) => {
    const tr = el("tr");
    tr.appendChild(el("td", "mono", c.tool));
    CONTROLS.forEach((ctrl) => {
      const d = c.decisions.find((x) => x.control === ctrl);
      const td = d
        ? el("td", d.decision === "ALLOW" ? "cell-allow" : "cell-block",
          d.decision === "ALLOW" ? "✓ ALLOW" : "✗ BLOCK")
        : el("td", "cell-na", "n/a");
      if (d) td.title = d.reason;
      tr.appendChild(td);
    });
    const privileged = !BASELINE_TOOLS.includes(c.tool);
    tr.appendChild(c.outcome === "EXECUTED"
      ? el("td", privileged ? "cell-impact" : "cell-exec", privileged ? "✗ EXECUTED" : "● EXECUTED")
      : el("td", "cell-block", "✓ BLOCKED"));
    body.appendChild(tr);
  });
  table.appendChild(body);
  box.replaceChildren(table, el("p", "muted small", "Hover a cell for the control's reason. A call runs only if every control allows it."));
}

// --- evidence -------------------------------------------------------------
function explainResult(run) {
  const ev = run.evidence;
  switch (run.final_result) {
    case "ATTACK_SUCCESS":
      return `No injection was stopped: get_asset_credentials executed and send_report carried the access token to ${
        (run.tool_calls.find((c) => c.tool === "send_report") || { arguments: {} }).arguments.destination || "an external destination"}.`;
    case "PARTIALLY_MITIGATED":
      return "A credential was retrieved (sensitive data accessed) but egress was blocked, so it did not leave.";
    case "ATTACK_BLOCKED":
      return `Injected instructions were detected and the agent was influenced, but every privileged call was blocked (${ev.blocked_tools.join(", ")}).`;
    default:
      return "No injection signal in the retrieved context; only the knowledge-base search ran.";
  }
}

function renderEvidence(run) {
  const box = $("evidence-body");
  box.className = "";
  const ev = run.evidence;
  const conclusion = el("div", `conclusion c-${RESULT_TONE[run.final_result]}`);
  conclusion.appendChild(resultBadge(run.final_result));
  conclusion.appendChild(el("p", null, explainResult(run)));
  const support = el("ul", "support");
  [
    ["Sensitive credential accessed", run.sensitive_accessed ? "yes" : "no"],
    ["Data exfiltrated", run.data_exfiltrated ? "yes" : "no"],
    ["Executed tools", ev.executed_tools.join(", ") || "none"],
    ["Blocked tools", ev.blocked_tools.join(", ") || "none"],
  ].forEach(([k, v]) => support.appendChild(el("li", null, `${k}: ${v}`)));
  conclusion.appendChild(el("p", "sub", "Supported by"));
  conclusion.appendChild(support);

  box.replaceChildren(
    kv([
      ["Run ID", el("code", null, run.run_id)],
      ["Mode", run.mode],
      ["Attack technique", run.attack_technique],
      ["Source", run.context_source],
      ["Trust level", run.trust_level],
      ["Payload sha256", el("code", "wrap", run.payload_sha256)],
      ["Requested tools", toolList(run.tool_requested, () => "warn")],
      ["Executed tools", toolList(ev.executed_tools, (t) => (BASELINE_TOOLS.includes(t) ? "info" : "danger"))],
      ["Controls evaluated", run.security_controls_evaluated.join(", ") || "none (policy layer off)"],
      ["Security impact", run.security_impact],
      ["Retest", run.retest_result || "n/a"],
    ]),
    conclusion,
  );

  // Same attack, different posture: prove it with the hash.
  const attack = state.runs.attack;
  if (run.mode === "secure" && attack) {
    const same = attack.payload_sha256 === run.payload_sha256;
    box.appendChild(el("p", same ? "callout c-safe" : "callout c-warn",
      same ? `✓ Same payload as ${attack.run_id} (sha256 match). Same attack, different posture.`
        : `⚠ Payload differs from ${attack.run_id}; this replay proves nothing about the control.`));
  }
  loadHistory();
}

async function loadHistory() {
  const { findings } = await api("GET", "/api/evidence");
  const box = $("evidence-history");
  if (!findings.length) { box.replaceChildren(el("p", "muted small", "No evidence recorded yet.")); return; }
  const table = el("table", "matrix");
  const head = el("tr");
  ["Run", "Mode", "Result", "Payload sha256", "Executed"].forEach((h) => head.appendChild(el("th", null, h)));
  table.appendChild(el("thead")).appendChild(head);
  const body = el("tbody");
  findings.slice(-10).reverse().forEach((f) => {
    const tr = el("tr");
    tr.appendChild(el("td", "mono", f.run_id || "—"));
    tr.appendChild(el("td", null, f.mode));
    const td = el("td"); td.appendChild(resultBadge(f.final_result)); tr.appendChild(td);
    tr.appendChild(el("td", "mono", shortHash(f.payload_sha256)));
    tr.appendChild(el("td", "mono", ((f.evidence || {}).executed_tools || []).join(", ")));
    body.appendChild(tr);
  });
  table.appendChild(body);
  box.replaceChildren(table);
}

// --- create test ----------------------------------------------------------
function renderCreated(data, run) {
  const c = data.case, p = c.provenance;
  $("created-test").hidden = false;
  const flow = el("ol", "provenance");
  const step = (title, rows) => {
    const li = el("li", "prov-step");
    li.appendChild(el("span", "eyebrow", title));
    li.appendChild(kv(rows));
    return li;
  };
  flow.appendChild(step("Finding", [
    ["Source run", el("code", null, p.source_run_id)],
    ["Result", resultBadge(p.original_result)],
    ["Impact", p.security_impact],
  ]));
  flow.appendChild(step("Evidence", [
    ["Payload sha256", el("code", "wrap", p.attack_payload_sha256)],
    ["Trust", p.trust_level],
    ["Requested", p.requested_tools.join(", ")],
    ["Executed", p.executed_tools.join(", ")],
  ]));
  flow.appendChild(step("Regression test", [
    ["Generated case", el("code", null, `tests/security_cases/${data.file}`)],
    ["Security invariant", c.security_invariant],
    ["Prohibited tools", c.prohibited_tools.join(", ")],
    ["Controls", c.controls.join(", ")],
    ["Expected secure result", resultBadge(c.expected_secure_result)],
  ]));
  $("created-body").replaceChildren(flow);
  if (run && run.payload_sha256 !== p.attack_payload_sha256) {
    $("created-body").appendChild(el("p", "callout c-warn", "⚠ Provenance hash does not match the displayed run."));
  }
}

// --- regression suite -----------------------------------------------------
function renderCaseList() {
  if (state.suite) return;
  $("suite-summary").textContent =
    `${state.cases.length} security cases in tests/security_cases/. Run VERIFY to replay them.`;
  const ul = el("ul", "case-list");
  state.cases.forEach((c) => ul.appendChild(el("li", null,
    `${c.id} — ${c.title}${c.source_run_id ? ` (from ${c.source_run_id})` : ""}`)));
  $("suite-table").replaceChildren(ul);
}

function renderSuite(suite) {
  const gate = suite.status === "PASSED";
  const summary = el("div", "suite-summary");
  summary.appendChild(el("span", null, `Passed: ${suite.passed}`));
  summary.appendChild(el("span", null, `Failed: ${suite.failed}`));
  summary.appendChild(badge(`SECURITY GATE: ${suite.status}`, gate ? "safe" : "danger", gate ? "✓" : "✗"));
  if (suite.critical) summary.appendChild(badge("Critical: a boundary was crossed", "danger", "⚠"));
  summary.appendChild(el("span", "muted small", `posture: ${suite.control_profile}`));
  $("suite-summary").className = "";
  $("suite-summary").replaceChildren(summary);

  const table = el("table", "matrix");
  const head = el("tr");
  ["Case", "Title", "Attack replay", "Secure posture", "Gate"].forEach((h) => head.appendChild(el("th", null, h)));
  table.appendChild(el("thead")).appendChild(head);
  const body = el("tbody");
  suite.cases.forEach((c) => {
    const replayOk = c.observed_vulnerable_result === c.expected_vulnerable_result;
    const executedProhibited = c.prohibited_tools.filter((t) => c.executed_tools.includes(t));
    const secureOk = c.observed_secure_result === c.expected_secure_result && !executedProhibited.length;
    const tr = el("tr");
    tr.appendChild(el("td", "mono", c.id));
    tr.appendChild(el("td", null, c.title));
    tr.appendChild(el("td", replayOk ? "cell-allow" : "cell-block", replayOk ? "✓ PASS" : "✗ FAIL"));
    tr.appendChild(el("td", secureOk ? "cell-allow" : "cell-block", secureOk ? "✓ PASS" : "✗ FAIL"));
    tr.appendChild(el("td", c.status === "PASSED" ? "cell-allow" : "cell-block", c.status === "PASSED" ? "✅" : "❌"));
    body.appendChild(tr);
  });
  table.appendChild(body);
  $("suite-table").replaceChildren(table);

  const fails = $("suite-failures");
  fails.replaceChildren();
  suite.cases.filter((c) => c.status !== "PASSED").forEach((c) => {
    const card = el("article", "fail-card");
    card.appendChild(el("h3", null, `✗ ${c.id} — ${c.title}`));
    const prohibited = c.prohibited_tools.filter((t) => c.executed_tools.includes(t));
    card.appendChild(kv([
      ["Expected", c.expected_secure_result],
      ["Observed", c.observed_secure_result || "case could not be executed"],
      ["Prohibited tool executed", prohibited.join(", ") || "none"],
      ["Trust boundary", c.trust_boundary],
      ["Agent influenced", yesNo(c.agent_influenced, "warn")],
      ["Boundary crossed", yesNo(c.boundary_crossed, "danger")],
      ["Reason", c.reason],
    ]));
    fails.appendChild(card);
  });
  renderPipeline();
}

function renderPipeline() {
  const suite = state.suite;
  const regressed = state.profile !== BASELINE;
  const steps = [
    ["Developer change", regressed ? "⚠ broadened incident access" : "● baseline posture", regressed ? "warn" : "info"],
    ["pytest", "runs in CI (not executed by this page)", "idle"],
    ["AgentBreak verify", suite ? `${suite.passed} passed · ${suite.failed} failed` : "not run yet", suite ? (suite.status === "PASSED" ? "safe" : "danger") : "idle"],
    ["Security gate", suite ? (suite.status === "PASSED" ? "✓ PASSED" : "✗ FAILED") : "—", suite ? (suite.status === "PASSED" ? "safe" : "danger") : "idle"],
    ["Outcome", suite ? (suite.status === "PASSED" ? "change can proceed" : "deployment would be blocked") : "—", suite ? (suite.status === "PASSED" ? "safe" : "danger") : "idle"],
  ];
  $("pipeline").replaceChildren(...steps.map(([t, s, tone]) => {
    const li = el("li", `n-${tone}`);
    li.appendChild(el("span", "node-label", t));
    li.appendChild(el("span", "node-state", s));
    return li;
  }));
}

// --- mappings / posture ---------------------------------------------------
function renderMappings(m) {
  $("mappings-source").textContent = `Source: ${m.source}`;
  const wrap = el("div", "mapping-groups");
  const group = (title, items) => {
    const g = el("div", "mapping-group");
    g.appendChild(el("h3", null, title));
    const ul = el("ul", "mapping-list");
    items.forEach((i) => {
      const li = el("li");
      li.appendChild(el("span", "mapping-badge", i.code || i.id));
      li.appendChild(el("strong", null, i.title));
      if (i.why) li.appendChild(el("span", "muted small", i.why));
      ul.appendChild(li);
    });
    g.appendChild(ul);
    return g;
  };
  wrap.appendChild(group("OWASP LLM Top 10 (v1.1)", m.owasp_llm));
  wrap.appendChild(group("MITRE ATLAS", m.mitre_atlas));
  $("mappings-body").replaceChildren(wrap);
}

function applyState(s) {
  state.profile = s.control_profile;
  state.profiles = s.profiles;
  state.cases = s.cases;
  $("scenario-name").textContent = s.scenario;
  $("scenario-task").textContent = s.task;
  const regressed = state.profile !== BASELINE;
  const pb = $("posture-badge");
  pb.className = `badge-lg b-${regressed ? "danger" : "safe"}`;
  pb.textContent = regressed ? "⚠ Workshop regression posture" : "✓ Baseline posture";
  $("regression-banner").hidden = !regressed;
  const desc = (state.profiles.find((p) => p.name === state.profile) || {}).description || "";
  $("regression-banner-text").textContent = desc;
  renderCaseList();
  renderPipeline();
}

// --- workshop flow --------------------------------------------------------
function nextAction() {
  const f = state.flow;
  if (!f.normal) return {
    label: "Run normal", tone: "info", title: "Run the normal scenario",
    help: "Clean knowledge base, policy layer engaged. Hardening must not break legitimate use.",
    run: () => runMode("normal"),
  };
  if (!f.attack) return {
    label: "Run attack", tone: "danger", title: "Run the attack",
    help: "Poisoned document, policy layer OFF (the vulnerable path). Watch what the injected text makes the agent do.",
    run: () => runMode("attack"),
  };
  if (!f.test) return {
    label: "Create regression test", tone: "warn", title: `Turn ${state.runs.attack.run_id} into a regression test`,
    help: "Every successful AI attack should become a security test. Uses the recorded payload and its sha256.",
    run: createTest,
  };
  if (!f.applied) return {
    label: "Introduce regression", tone: "danger", title: "Ship an \"innocent\" change",
    help: "A teammate lets the incident agent read asset credentials directly and drops the human approval. Applied in memory only, never to source files.",
    run: () => setProfile(BROADENED, "applied"),
  };
  if (!f.regression) return {
    label: "Verify", tone: "warn", title: "Replay the attack and run the regression suite",
    help: "Same payload under the changed posture, then the same runner as `agentbreak verify`.",
    run: () => retest("regression"),
  };
  if (!f.fix) return {
    label: "Fix", tone: "safe", title: "Restore the baseline posture",
    help: "Revert the change. Don't add a sentence to a system prompt: controls live outside the model.",
    run: () => setProfile(BASELINE, "fix"),
  };
  if (!f.verify) return {
    label: "Retest", tone: "safe", title: "Replay the same attack and verify again",
    help: "Same attack, different posture. The gate should be green again.",
    run: () => retest("verify"),
  };
  return {
    label: "Done", tone: "safe", title: "Walkthrough complete",
    help: "Attack → Evidence → Regression test → CI gate. Use \"reset walkthrough state\" to start again; evidence and generated regression cases are kept.",
    run: null,
  };
}

function renderFlow() {
  const f = state.flow;
  const current = STEPS.find(([k]) => !f[k]);
  $("timeline").replaceChildren(...STEPS.map(([k, label], i) => {
    const done = !!f[k];
    const li = el("li", done ? "done" : current && current[0] === k ? "current" : "");
    li.appendChild(el("span", "step-icon", done ? "✓" : String(i + 1)));
    li.appendChild(el("span", "step-label", label));
    if (current && current[0] === k) li.setAttribute("aria-current", "step");
    return li;
  }));
  const next = nextAction();
  $("next-title").textContent = next.title;
  $("next-help").textContent = next.help;
  const btn = $("next-btn");
  btn.textContent = state.busy ? "Running…" : next.label;
  btn.className = `cta cta-${next.tone}`;
  btn.disabled = state.busy || !next.run;
  document.querySelectorAll(".chip-btn").forEach((b) => { b.disabled = state.busy; });
}

function showError(msg) {
  const e = $("next-error");
  e.hidden = !msg;
  e.textContent = msg || "";
}

async function busy(fn) {
  state.busy = true; showError(""); renderFlow();
  try { await fn(); } catch (err) { showError(err.message); }
  finally { state.busy = false; renderFlow(); }
}

async function runMode(mode) {
  const run = await api("POST", "/api/scenarios/indirect-injection/run", { mode });
  state.runs[mode] = run;
  state.lastRun = run;
  if (mode === "normal") state.flow.normal = true;
  if (mode === "attack") { state.flow.attack = true; state.flow.evidence = true; }
  renderRun(run);
  return run;
}

async function createTest() {
  const run = state.runs.attack;
  const data = await api("POST", `/api/runs/${encodeURIComponent(run.run_id)}/create-test`);
  state.created = data;
  state.flow.test = true;
  renderCreated(data, run);
  applyState(await api("GET", "/api/trust/state"));
  $("created-test").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function setProfile(profile, flag) {
  applyState(await api("POST", "/api/workshop/profile", { profile }));
  if (flag) state.flow[flag] = true;
}

async function verify() {
  const suite = await api("POST", "/api/regressions/verify");
  state.suite = suite;
  renderSuite(suite);
  return suite;
}

async function retest(flag) {
  await runMode("secure");
  const suite = await verify();
  if (flag === "regression") state.flow.regression = suite.status === "FAILED";
  if (flag === "verify" && suite.status === "PASSED") { state.flow.verify = true; state.flow.gate = true; }
  if (flag === "regression" && suite.status !== "FAILED") {
    showError("The suite still passes under this posture. Did the regression get applied?");
  }
  $("regressions").scrollIntoView({ behavior: "smooth", block: "start" });
}

// Resets this page's walkthrough and the control profile only. Evidence
// (artifacts/attack_report.*) and generated AB-REG-* cases are kept on purpose.
async function resetFlow() {
  state.flow = {}; state.runs = {}; state.created = null; state.suite = null;
  $("created-test").hidden = true;
  $("suite-failures").replaceChildren();
  await setProfile(BASELINE);
}

// --- wiring ---------------------------------------------------------------
$("next-btn").addEventListener("click", () => {
  const next = nextAction();
  if (next.run) busy(next.run);
});
document.querySelectorAll(".chip-btn[data-mode]").forEach((b) =>
  b.addEventListener("click", () => busy(() => runMode(b.dataset.mode))));
$("reset-flow").addEventListener("click", () => busy(resetFlow));

(async () => {
  try {
    const s = await api("GET", "/api/trust/state");
    applyState(s);
    renderMappings(s.mappings);
    loadHistory();
  } catch (err) { showError(err.message); }
  renderFlow();
})();

// AgentBreak frontend. Plain JS, no framework. Uses fetch + JSON APIs.
// The diary unlocks a card the moment a vulnerability is exploited in the chat.

const $ = (id) => document.getElementById(id);
const messages = $("messages");
const slots = $("diary-slots");
const cardTpl = $("card-tpl");

// Per-card state kept across re-renders: how many hints the user has revealed.
const hintShown = {};

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function bubble(role, text, tag) {
  const b = el("div", `bubble ${role}`, text);
  if (tag) b.appendChild(el("span", "tag", tag));
  messages.appendChild(b);
  messages.scrollTop = messages.scrollHeight;
}

// --- diary ----------------------------------------------------------------
function renderCard(entry, position) {
  const node = cardTpl.content.firstElementChild.cloneNode(true);
  node.dataset.cid = entry.code;
  node.querySelector(".vuln-pos").textContent = `#${position}`;
  node.querySelector(".vuln-title").textContent = `Vulnerability #${position}`;
  const badge = node.querySelector(".badge");
  const reveal = node.querySelector(".vuln-reveal");
  const placeholder = node.querySelector(".vuln-placeholder");

  if (entry.unlocked) {
    node.classList.remove("locked");
    node.classList.add("unlocked");
    badge.textContent = entry.severity;
    badge.className = `badge sev-${entry.severity}`;
    placeholder.hidden = true;
    reveal.hidden = false;
    node.querySelector(".vuln-category").textContent = `${entry.code} — ${entry.title}`;
    node.querySelector(".vuln-summary").textContent = entry.summary;
    node.querySelector(".vuln-evidence").textContent = `✔ ${entry.evidence}`;
    node.querySelector(".vuln-mitigation-text").textContent = entry.remediation;
  }

  // Hints (available whether locked or not).
  const list = node.querySelector(".hint-list");
  const btn = node.querySelector(".hint-btn");
  const status = node.querySelector(".hint-status");
  const hints = entry.hints || [];
  const shown = hintShown[entry.code] || 0;
  for (let i = 0; i < shown && i < hints.length; i++) {
    list.appendChild(el("li", null, hints[i]));
  }
  const sync = () => {
    const n = hintShown[entry.code] || 0;
    if (n >= hints.length) {
      btn.disabled = true;
      status.textContent = hints.length ? "All hints revealed." : "No hints for this card.";
    } else {
      status.textContent = `${n} / ${hints.length} hints revealed.`;
    }
  };
  btn.addEventListener("click", () => {
    const n = hintShown[entry.code] || 0;
    if (n >= hints.length) return;
    list.appendChild(el("li", null, hints[n]));
    hintShown[entry.code] = n + 1;
    sync();
  });
  sync();
  return node;
}

function renderJournal(payload) {
  slots.innerHTML = "";
  const { unlocked, total } = payload.progress;
  $("progress-label").textContent = `${unlocked} / ${total} unlocked`;
  $("progress-fill").style.width = `${(unlocked / total) * 100}%`;
  payload.entries.forEach((e, i) => slots.appendChild(renderCard(e, i + 1)));
}

function flashUnlocked(codes, entries) {
  codes.forEach((code) => {
    const card = slots.querySelector(`.vuln-card[data-cid="${code}"]`);
    if (card) card.scrollIntoView({ behavior: "smooth", block: "nearest" });
    const entry = entries.find((e) => e.code === code);
    const label = entry ? `${entry.code} — ${entry.title}` : code;
    bubble("unlocked-note", `🔓 Diary unlocked: ${label}`);
  });
}

async function loadJournal() {
  const r = await fetch("/api/journal");
  renderJournal(await r.json());
}

// --- chat -----------------------------------------------------------------
async function sendChat(message) {
  bubble("user", message);
  try {
    const r = await fetch("/api/chat", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    const data = await r.json();
    const tag = data.actions && data.actions.length
      ? `actions: ${data.actions.join(", ")}`
      : `backend: ${data.backend}`;
    bubble("bot", data.text, tag);
    if (data.journal) renderJournal(data.journal);
    if (data.newly_unlocked && data.newly_unlocked.length) {
      flashUnlocked(data.newly_unlocked, data.journal.entries);
    }
  } catch (e) {
    bubble("bot", "Error contacting the chatbot.");
  }
}

// --- actions --------------------------------------------------------------
async function generateReport() {
  const r = await fetch("/api/report", { method: "POST" });
  const data = await r.json();
  $("report-text").textContent = data.markdown;
  $("report-modal").classList.remove("hidden");
  loadJournal();
}

async function resetLab() {
  const r = await fetch("/api/journal/reset", { method: "POST" });
  for (const k of Object.keys(hintShown)) delete hintShown[k];
  renderJournal(await r.json());
  messages.innerHTML = "";
  greet();
}

function greet() {
  bubble("bot",
    "Hi, I'm HelpBot for Contoso Technologies. I can help with orders, refunds " +
    "and account questions. How can I assist you today?",
    "backend: simulator");
}

// --- wiring ---------------------------------------------------------------
$("chat-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const input = $("chat-input");
  const msg = input.value.trim();
  if (!msg) return;
  input.value = "";
  sendChat(msg);
});
$("chat-reset").addEventListener("click", () => { messages.innerHTML = ""; greet(); });
$("open-report").addEventListener("click", generateReport);
$("reset-journal").addEventListener("click", resetLab);
$("close-report").addEventListener("click", () => $("report-modal").classList.add("hidden"));

greet();
loadJournal();

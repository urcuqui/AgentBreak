// Frontend for the demo. Plain ES modules, no framework.

const stage = document.getElementById("stage");
const healthEl = document.getElementById("health");
const useLlmEl = document.getElementById("use-llm");
const modelEl = document.getElementById("model");
const buttons = document.querySelectorAll(".btn[data-mode]");
const clearBtn = document.getElementById("btn-clear");

let activeStream = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function append(node) {
  stage.appendChild(node);
  node.scrollIntoView({ behavior: "smooth", block: "end" });
}

function clearStage() {
  stage.innerHTML = "";
}

function refreshHealth() {
  const model = modelEl.value.trim() || "llama3.2:3b";
  fetch(`/api/health?model=${encodeURIComponent(model)}`)
    .then((r) => r.json())
    .then((data) => {
      let status;
      if (!data.ollama_available) {
        status = `<span class="ko">[--]</span> Ollama not detected. Simulator will be used.`;
      } else if (!data.model_present) {
        const installed = (data.installed_models || []).join(", ") || "none";
        status =
          `<span class="ko">[!]</span> Ollama up but model <code>${data.model}</code> is not pulled. ` +
          `Run <code>ollama pull ${data.model}</code>. Installed: ${installed}. Simulator will be used.`;
      } else {
        status = `<span class="ok">[OK]</span> Ollama detected (model=<code>${data.model}</code>)`;
      }
      healthEl.innerHTML = status;
    })
    .catch(() => {
      healthEl.innerHTML = `<span class="ko">[--]</span> Health check failed.`;
    });
}

function setBusy(busy) {
  buttons.forEach((b) => (b.disabled = busy));
}

function renderEvent(ev) {
  switch (ev.type) {
    case "banner": {
      const node = el("div", `banner ${ev.level || "neutral"}`);
      node.appendChild(el("h2", null, ev.title));
      if (ev.subtitle) node.appendChild(el("div", "sub", ev.subtitle));
      append(node);
      break;
    }
    case "info": {
      const node = el("div", "event info");
      node.appendChild(el("span", "num", "i"));
      node.appendChild(el("span", "msg", ev.message));
      append(node);
      break;
    }
    case "step": {
      const node = el("div", `event ${ev.level || "neutral"}`);
      node.appendChild(el("span", "num", `[${ev.n}]`));
      node.appendChild(el("span", "msg", ev.message));
      if (ev.detail) node.appendChild(el("span", "detail", ev.detail));
      append(node);
      break;
    }
    case "document": {
      const node = el("div", "doc");
      node.appendChild(el("h3", null, ev.title));
      node.appendChild(
        el(
          "div",
          "meta",
          `${ev.source} · trust_level=${ev.trust_level}`
        )
      );
      const pre = el("pre", null, ev.wrapped_text ?? ev.content);
      node.appendChild(pre);
      append(node);
      break;
    }
    case "tools_tree": {
      const wrap = el("div", "tree");
      wrap.appendChild(el("strong", null, "Allowed tools by task"));
      const ul = el("ul");
      Object.entries(ev.allowed).forEach(([task, tools]) => {
        const li = el("li", "task", task);
        const inner = el("ul");
        tools.forEach((t) => inner.appendChild(el("li", null, t)));
        li.appendChild(inner);
        ul.appendChild(li);
      });
      wrap.appendChild(ul);
      append(wrap);
      break;
    }
    case "suspicious_findings": {
      const wrap = el("div", "findings");
      ev.findings.slice(0, 5).forEach((f) => {
        wrap.appendChild(
          el("div", "finding", `[!] pattern=${JSON.stringify(f.pattern)}`)
        );
      });
      append(wrap);
      break;
    }
    case "policy_decisions": {
      const wrap = el("div", "decisions");
      ev.decisions.forEach((d) => {
        const row = el("div", "decision");
        const mark = el("span", d.allowed ? "ok" : "ko", d.allowed ? "[OK] " : "[X]  ");
        row.appendChild(mark);
        row.appendChild(document.createTextNode(`${d.policy_name}: ${d.reason}`));
        wrap.appendChild(row);
      });
      append(wrap);
      break;
    }
    case "outcome": {
      const node = el("div", `outcome ${ev.success ? "success" : "failure"}`);
      const mark = ev.success ? "[OK]" : "[X]";
      node.appendChild(document.createTextNode(`${mark} ${ev.title}`));
      const sub = el("div");
      sub.style.fontWeight = "400";
      sub.style.marginTop = "0.4rem";
      sub.style.opacity = "0.85";
      sub.textContent = ev.message;
      node.appendChild(sub);
      append(node);
      break;
    }
    case "done":
      setBusy(false);
      break;
  }
}

function runMode(mode) {
  if (activeStream) activeStream.close();
  clearStage();
  setBusy(true);
  const params = new URLSearchParams({
    use_llm: useLlmEl.checked ? "true" : "false",
    model: modelEl.value.trim() || "llama3.2:3b",
  });
  const es = new EventSource(`/api/run/${mode}?${params.toString()}`);
  activeStream = es;
  es.onmessage = (msg) => {
    try {
      renderEvent(JSON.parse(msg.data));
    } catch (e) {
      console.error("bad event", msg.data, e);
    }
  };
  es.onerror = () => {
    es.close();
    activeStream = null;
    setBusy(false);
  };
}

buttons.forEach((b) => b.addEventListener("click", () => runMode(b.dataset.mode)));
clearBtn.addEventListener("click", clearStage);
modelEl.addEventListener("change", refreshHealth);
useLlmEl.addEventListener("change", refreshHealth);
refreshHealth();

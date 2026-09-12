(() => {
  const SITE = {
    "grok.com": { provider: "grok", model: "Grok Web" },
    "gemini.google.com": { provider: "gemini", model: "Gemini Web" },
    "chatgpt.com": { provider: "chatgpt", model: "ChatGPT Web" },
    "claude.ai": { provider: "claude-web", model: "Claude Web" }
  }[location.hostname];
  if (!SITE) return;

  const ADAPTER_VERSION = "web-ai-0.1.0";
  const emitted = new Set();
  let pendingFiles = [];
  let lastPrompt = "";
  let activeTurnId = null;
  let generationStartedAt = 0;
  let responseTimer = null;
  let lastResponseText = "";
  let lastReasoningText = "";

  function fingerprint(value) {
    let hash = 2166136261;
    for (let i = 0; i < value.length; i += 1) {
      hash ^= value.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
  }

  function send(eventType, text, extra = {}) {
    const material = `${eventType}|${text || ""}|${extra.mediaURL || ""}|${extra.heartbeatAt || ""}|${location.href}`;
    const key = fingerprint(material);
    if (["connected", "result"].includes(eventType) && emitted.has(key)) return null;
    if (["connected", "result"].includes(eventType)) emitted.add(key);
    if (emitted.size > 2048) emitted.clear();
    const eventId = crypto.randomUUID();
    chrome.runtime.sendMessage({
      source: "agentreins-web-ai",
      event: {
        schemaVersion: 1, adapterVersion: ADAPTER_VERSION, provider: SITE.provider,
        modelLabel: SITE.model, eventId, eventType, timestamp: new Date().toISOString(),
        url: location.href, title: document.title, text: text || null, ...extra
      }
    });
    return eventId;
  }

  function editableValue(element) {
    return (element?.value || element?.innerText || element?.textContent || "").trim();
  }

  function visiblePrompt() {
    const candidates = [...document.querySelectorAll("textarea, [contenteditable='true'], input[type='text']")];
    const visible = candidates.filter(item => item.offsetParent !== null && !item.disabled);
    return editableValue(visible.find(item => editableValue(item)) || visible[0]);
  }

  document.addEventListener("input", event => {
    const value = editableValue(event.composedPath?.()[0] || event.target);
    if (value) lastPrompt = value;
  }, true);

  async function describeFiles(files) {
    return Promise.all([...files].map(async file => {
      const canHash = file.size <= 64 * 1024 * 1024;
      const digest = canHash ? await crypto.subtle.digest("SHA-256", await file.arrayBuffer()) : null;
      return { name: file.name, type: file.type || "application/octet-stream", size: file.size,
        sha256: digest ? [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("") : null,
        hashStatus: canHash ? "complete" : "skipped_over_64_mb" };
    }));
  }

  document.addEventListener("change", async event => {
    if (!(event.target instanceof HTMLInputElement) || event.target.type !== "file" || !event.target.files?.length) return;
    pendingFiles = await describeFiles(event.target.files);
    send("upload", pendingFiles.map(f => `${f.name} (${f.type}, ${f.size} bytes, ${f.sha256 ? `sha256:${f.sha256}` : f.hashStatus})`).join("\n"), { files: pendingFiles });
  }, true);

  function submitPrompt() {
    const prompt = visiblePrompt() || lastPrompt;
    if (!prompt || prompt === lastResponseText) return;
    lastPrompt = prompt;
    activeTurnId = send("prompt", prompt, { files: pendingFiles });
    generationStartedAt = Date.now();
    pendingFiles = [];
  }

  document.addEventListener("submit", () => queueMicrotask(submitPrompt), true);
  document.addEventListener("keydown", event => {
    if (event.key === "Enter" && !event.shiftKey && (event.target.matches?.("textarea") || event.target.isContentEditable)) {
      lastPrompt = editableValue(event.target) || visiblePrompt();
      queueMicrotask(submitPrompt);
    }
  }, true);
  document.addEventListener("pointerdown", event => {
    const button = event.target.closest?.("button, [role='button']");
    if (!button) return;
    const candidate = visiblePrompt();
    if (candidate) lastPrompt = candidate;
    const label = `${button.innerText || ""} ${button.getAttribute("aria-label") || ""}`.toLowerCase();
    if (/send|submit|generate|create|发送|提交|生成|创建/.test(label)) queueMicrotask(submitPrompt);
  }, true);

  const RESPONSE_SELECTORS = {
    "grok": ["[data-message-author-role='assistant']", "[class*='markdown']"],
    "gemini": ["model-response", "message-content", ".model-response-text", ".response-container-content"],
    "chatgpt": ["[data-message-author-role='assistant']", "[data-testid*='conversation-turn'] .markdown"],
    "claude-web": ["[data-testid='assistant-message']", "[data-is-streaming]", ".font-claude-message"]
  }[SITE.provider];

  const REASONING_SELECTORS = {
    "grok": ["[data-testid*='reasoning']", "[class*='reasoning']", "[class*='thinking']"],
    "gemini": ["thoughts", "[class*='thought']", "[class*='thinking']", "[aria-label*='thinking' i]"],
    "chatgpt": ["[data-testid*='reasoning']", "[class*='reasoning']", "[aria-label*='thinking' i]"],
    "claude-web": ["[data-testid*='thinking']", "[class*='thinking']", "[aria-label*='thinking' i]"]
  }[SITE.provider];

  function visibleAssistantResponse() {
    return [...document.querySelectorAll(RESPONSE_SELECTORS.join(","))]
      .filter(item => item.offsetParent !== null && !item.closest("form"))
      .map(editableValue).filter(text => text.length >= 2 && text !== lastPrompt).at(-1) || "";
  }

  function visibleReasoning() {
    return [...document.querySelectorAll(REASONING_SELECTORS.join(","))]
      .filter(item => item.offsetParent !== null)
      .map(editableValue).filter(text => text.length >= 2).at(-1) || "";
  }

  function scheduleResponseCapture() {
    if (!activeTurnId || Date.now() - generationStartedAt > 20 * 60 * 1000) return;
    clearTimeout(responseTimer);
    responseTimer = setTimeout(() => {
      const reasoning = visibleReasoning();
      if (reasoning && reasoning !== lastReasoningText) {
        lastReasoningText = reasoning;
        send("reasoning", reasoning, { turnId: activeTurnId, visibility: "rendered-in-page" });
      }
      const text = visibleAssistantResponse();
      if (!text || text === lastResponseText) return;
      lastResponseText = text;
      send("response", text, { turnId: activeTurnId });
    }, 1200);
  }

  new MutationObserver(scheduleResponseCapture).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  send("connected", `${SITE.model} tab connected`);
  send("diagnostic", JSON.stringify({ adapterVersion: ADAPTER_VERSION, provider: SITE.provider,
    textareas: document.querySelectorAll("textarea").length,
    contenteditables: document.querySelectorAll("[contenteditable='true']").length,
    frames: document.querySelectorAll("iframe").length }));
  setInterval(() => send("heartbeat", null, { heartbeatAt: new Date().toISOString() }), 30000);
})();

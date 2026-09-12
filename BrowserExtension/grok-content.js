(() => {
  const ADAPTER_VERSION = "grok-0.3.0";
  const emitted = new Set();
  let pendingFiles = [];
  let lastPrompt = "";
  let activeTurnId = null;
  let generationStartedAt = 0;
  let responseTimer = null;
  let lastResponseText = "";

  function mode() {
    return new URL(location.href).searchParams.get("type") || "unknown";
  }

  function fingerprint(value) {
    let hash = 2166136261;
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
  }

  function send(eventType, text, extra = {}) {
    const material = `${eventType}|${text || ""}|${extra.mediaURL || ""}|${extra.heartbeatAt || ""}|${location.href}`;
    const key = fingerprint(material);
    const shouldDeduplicate = eventType === "result" || eventType === "connected";
    if (shouldDeduplicate && emitted.has(key)) return null;
    if (shouldDeduplicate) {
      if (emitted.size >= 2048) emitted.clear();
      emitted.add(key);
    }
    const eventId = crypto.randomUUID();
    chrome.runtime.sendMessage({
      source: "agentreins-grok",
      event: {
        schemaVersion: 1,
        adapterVersion: ADAPTER_VERSION,
        eventId,
        eventType,
        timestamp: new Date().toISOString(),
        url: location.href,
        title: document.title,
        mode: mode(),
        text: text || null,
        ...extra
      }
    });
    return eventId;
  }

  function visiblePrompt() {
    const candidates = [...document.querySelectorAll("textarea, [contenteditable='true'], input[type='text']")];
    const element = candidates.find(item => item.offsetParent !== null && !item.disabled);
    return (element?.value || element?.innerText || element?.textContent || "").trim();
  }

  document.addEventListener("input", event => {
    const target = event.composedPath?.()[0] || event.target;
    const value = (target?.value || target?.innerText || target?.textContent || "").trim();
    if (value) lastPrompt = value;
  }, true);

  async function describeFiles(files) {
    return Promise.all([...files].map(async file => {
      const canHash = file.size <= 64 * 1024 * 1024;
      const digest = canHash ? await crypto.subtle.digest("SHA-256", await file.arrayBuffer()) : null;
      return {
        name: file.name,
        type: file.type || "application/octet-stream",
        size: file.size,
        sha256: digest ? [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("") : null,
        hashStatus: canHash ? "complete" : "skipped_over_64_mb"
      };
    }));
  }

  document.addEventListener("change", async event => {
    if (!(event.target instanceof HTMLInputElement) || event.target.type !== "file" || !event.target.files?.length) return;
    pendingFiles = await describeFiles(event.target.files);
    send("upload", pendingFiles.map(file => `${file.name} (${file.type}, ${file.size} bytes, ${file.sha256 ? `sha256:${file.sha256}` : file.hashStatus})`).join("\n"),
         { files: pendingFiles });
  }, true);

  function submitPrompt() {
    const prompt = visiblePrompt() || lastPrompt;
    if (!prompt) return;
    lastPrompt = prompt;
    activeTurnId = send("prompt", prompt, { files: pendingFiles });
    generationStartedAt = Date.now();
    pendingFiles = [];
  }

  document.addEventListener("submit", submitPrompt, true);
  document.addEventListener("keydown", event => {
    if (event.key === "Enter" && !event.shiftKey && (event.target.matches?.("textarea") || event.target.isContentEditable)) {
      lastPrompt = visiblePrompt();
      queueMicrotask(submitPrompt);
    }
  }, true);
  document.addEventListener("click", event => {
    const button = event.target.closest?.("button, [role='button']");
    const label = `${button?.innerText || ""} ${button?.getAttribute?.("aria-label") || ""}`.toLowerCase();
    if (/generate|create|生成|创建/.test(label)) {
      lastPrompt = visiblePrompt();
      queueMicrotask(submitPrompt);
    }
  }, true);
  document.addEventListener("pointerdown", event => {
    const button = event.target.closest?.("button, [role='button']");
    if (button) {
      const candidate = visiblePrompt();
      if (candidate) lastPrompt = candidate;
    }
  }, true);

  function inspectMedia(root) {
    if (!(root instanceof Element)) return;
    if (!activeTurnId || Date.now() - generationStartedAt > 20 * 60 * 1000) return;
    const candidates = [root, ...root.querySelectorAll("video[src], video source[src], img[src]")]
      .filter(item => item.matches?.("video[src], video source[src], img[src]"));
    for (const candidate of candidates) {
      const item = candidate.matches("source") ? candidate.closest("video") : candidate;
      if (!item) continue;
      const isVideo = item instanceof HTMLVideoElement;
      const ready = isVideo ? item.videoWidth >= 256 : item.naturalWidth >= 256;
      if (!ready) {
        item.addEventListener(isVideo ? "loadedmetadata" : "load", () => inspectMedia(item), { once: true });
        continue;
      }
      const mediaURL = candidate.currentSrc || candidate.src || item.currentSrc || item.src;
      if (!mediaURL || mediaURL.startsWith("data:")) continue;
      send("result", `${isVideo ? "video" : "image"} generated by Grok Imagine`, {
        mediaType: isVideo ? "video" : "image", mediaURL, turnId: activeTurnId
      });
    }
  }

  function visibleAssistantResponse() {
    const selectors = [
      "[data-message-author-role='assistant']",
      "[data-testid*='assistant']",
      "[data-testid*='message'] .markdown",
      "article .markdown",
      "[class*='markdown']"
    ];
    const candidates = [...document.querySelectorAll(selectors.join(","))]
      .filter(item => item.offsetParent !== null && !item.closest("form"))
      .map(item => (item.innerText || item.textContent || "").trim())
      .filter(text => text.length >= 2 && text !== lastPrompt);
    return candidates.at(-1) || "";
  }

  function scheduleResponseCapture() {
    if (!activeTurnId || Date.now() - generationStartedAt > 20 * 60 * 1000) return;
    clearTimeout(responseTimer);
    responseTimer = setTimeout(() => {
      const text = visibleAssistantResponse();
      if (!text || text === lastResponseText) return;
      lastResponseText = text;
      send("response", text, { turnId: activeTurnId });
    }, 1200);
  }

  const observer = new MutationObserver(records => {
    for (const record of records) {
      if (record.type === "attributes") inspectMedia(record.target);
      for (const node of record.addedNodes) inspectMedia(node);
    }
    scheduleResponseCapture();
  });
  observer.observe(document.documentElement, {
    childList: true, subtree: true, attributes: true, attributeFilter: ["src"]
  });
  send("connected", "Grok Imagine tab connected");
  send("diagnostic", JSON.stringify({
    adapterVersion: ADAPTER_VERSION,
    textareas: document.querySelectorAll("textarea").length,
    contenteditables: document.querySelectorAll("[contenteditable='true']").length,
    textInputs: document.querySelectorAll("input[type='text']").length,
    frames: document.querySelectorAll("iframe").length
  }));
  setInterval(() => send("heartbeat", null, { heartbeatAt: new Date().toISOString() }), 30000);
})();

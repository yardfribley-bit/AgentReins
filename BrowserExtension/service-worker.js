const HOST = "com.agentspec.agentreins.web";

const SUPPORTED_HOSTS = {
  "grok.com": "grok",
  "gemini.google.com": "gemini",
  "chatgpt.com": "chatgpt",
  "claude.ai": "claude-web"
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  let url;
  try { url = new URL(sender.tab?.url || ""); } catch (_) { url = null; }
  const provider = url ? SUPPORTED_HOSTS[url.hostname] : null;
  if (message?.source !== "agentreins-web-ai" || !provider || message.event?.provider !== provider) {
    sendResponse({ ok: false, error: "untrusted_sender" });
    return false;
  }
  const enriched = {
    ...message.event,
    tabId: sender.tab.id,
    windowId: sender.tab.windowId,
    provider,
    sessionId: `${provider}:${sender.tab.windowId}:${sender.tab.id}`,
    receivedAt: new Date().toISOString()
  };
  chrome.runtime.sendNativeMessage(HOST, enriched, response => {
    const error = chrome.runtime.lastError?.message;
    sendResponse(error ? { ok: false, error } : (response || { ok: false, error: "empty_response" }));
  });
  return true;
});

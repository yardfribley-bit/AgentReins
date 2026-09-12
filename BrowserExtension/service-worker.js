const HOST = "com.agentspec.agentreins.web";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.source !== "agentreins-grok" || sender.tab?.url?.startsWith("https://grok.com/") !== true) {
    sendResponse({ ok: false, error: "untrusted_sender" });
    return false;
  }
  const enriched = {
    ...message.event,
    tabId: sender.tab.id,
    windowId: sender.tab.windowId,
    sessionId: `grok:${sender.tab.windowId}:${sender.tab.id}`,
    receivedAt: new Date().toISOString()
  };
  chrome.runtime.sendNativeMessage(HOST, enriched, response => {
    const error = chrome.runtime.lastError?.message;
    sendResponse(error ? { ok: false, error } : (response || { ok: false, error: "empty_response" }));
  });
  return true;
});

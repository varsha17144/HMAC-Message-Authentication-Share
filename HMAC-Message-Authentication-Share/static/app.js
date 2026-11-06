/* app.js — Integrated Message Integrity & Authentication Lab
 *
 * Integrated Protocol Pipeline:
 *   Stage 1: Sender — Create authenticated packet (HMAC over timestamp + nonce + message)
 *   Stage 2: Network / Attacker — In-transit interception, dynamic tampering, and replay controls
 *   Stage 3: Receiver — Real-time backend verification (HMAC check, timestamp freshness, nonce cache)
 *   Stage 4: Live Protocol Audit Log — Chronological log of real server requests and responses
 *
 * All cryptographic and security decisions are made by the Flask backend.
 */

"use strict";

const $ = (id) => document.getElementById(id);

const els = {
  // Stage 1: Sender
  senderMessage: $("sender-message"),
  senderKey: $("sender-key"),
  btnCreatePacket: $("btn-create-packet"),
  btnCreateStale: $("btn-create-stale"),
  btnSenderReset: $("btn-sender-reset"),
  senderError: $("sender-error"),
  senderPacketView: $("sender-packet-view"),
  sOutMessage: $("s-out-message"),
  sOutTimestamp: $("s-out-timestamp"),
  sOutNonce: $("s-out-nonce"),
  sOutCanonical: $("s-out-canonical"),
  sOutHmac: $("s-out-hmac"),
  sOutSha256: $("s-out-sha256"),

  // Stage 2: Network & Attacker
  networkEmptyNotice: $("network-empty-notice"),
  networkPacketPanel: $("network-packet-panel"),
  transitStatusBadge: $("transit-status-badge"),
  transitMessage: $("transit-message"),
  transitTimestamp: $("transit-timestamp"),
  transitNonce: $("transit-nonce"),
  transitHmac: $("transit-hmac"),
  diffIndicator: $("diff-indicator"),
  diffContent: $("diff-content"),
  btnDeliverNormal: $("btn-deliver-normal"),
  btnTamperMsg: $("btn-tamper-msg"),
  btnReplayPacket: $("btn-replay-packet"),
  btnDeliverCustom: $("btn-deliver-custom"),

  // Stage 3: Receiver
  receiverKey: $("receiver-key"),
  btnReceiverVerify: $("btn-receiver-verify"),
  receiverAnalysisPanel: $("receiver-analysis-panel"),
  receiverVerdict: $("receiver-verdict"),
  receiverVerdictIcon: $("receiver-verdict-icon"),
  receiverVerdictTitle: $("receiver-verdict-title"),
  receiverVerdictDetail: $("receiver-verdict-detail"),
  resBadgeCrypto: $("res-badge-crypto"),
  resTagReceived: $("res-tag-received"),
  resTagExpected: $("res-tag-expected"),
  resBadgeFreshness: $("res-badge-freshness"),
  resFreshnessDetail: $("res-freshness-detail"),
  resBadgeNonce: $("res-badge-nonce"),
  resNonceDetail: $("res-nonce-detail"),
  resBadgeDecision: $("res-badge-decision"),
  resServerCode: $("res-server-code"),

  // Stage 4: Protocol Log & Controls
  logContainer: $("log-container"),
  btnResetNonceCache: $("btn-reset-nonce-cache"),
  btnClearLog: $("btn-clear-log"),
};

/* ---------- Protocol State ---------- */
let activeSenderPacket = null;   // The packet originally signed by Sender
let lastDeliveredPacket = null;  // The last packet successfully delivered to Receiver

/* ---------- API Helper ---------- */
async function postJSON(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

/* ---------- Protocol Audit Logger ---------- */
function appendLog(category, badgeClass, badgeText, messageText) {
  const now = new Date();
  const timeStr = now.toTimeString().split(" ")[0] + "." + String(now.getMilliseconds()).padStart(3, "0");

  const entry = document.createElement("div");
  entry.className = `log-entry ${category}`;

  entry.innerHTML = `
    <span class="log-time">[${timeStr}]</span>
    <span class="log-badge ${badgeClass}">${badgeText}</span>
    <span class="log-text">${messageText}</span>
  `;

  els.logContainer.appendChild(entry);
  els.logContainer.scrollTop = els.logContainer.scrollHeight;
}

/* ---------- Sender Helpers ---------- */
function showSenderError(msg) {
  els.senderError.textContent = msg;
  els.senderError.classList.remove("hidden");
}

function clearSenderError() {
  els.senderError.textContent = "";
  els.senderError.classList.add("hidden");
}

function renderSenderPacket(packet) {
  els.sOutMessage.textContent = packet.message;
  const dateStr = new Date(packet.timestamp * 1000).toLocaleTimeString();
  els.sOutTimestamp.textContent = `${packet.timestamp} (${dateStr})`;
  els.sOutNonce.textContent = packet.nonce;
  els.sOutCanonical.textContent = packet.authenticated_data;
  els.sOutHmac.textContent = packet.hmac;
  els.sOutSha256.textContent = packet.sha256 || "N/A";

  els.senderPacketView.classList.remove("hidden");
}

/* ---------- Network / Attacker Helpers ---------- */
function loadPacketIntoTransit(packet, badgeText, badgeClass) {
  els.networkEmptyNotice.classList.add("hidden");
  els.networkPacketPanel.classList.remove("hidden");

  els.transitMessage.value = packet.message;
  els.transitTimestamp.value = packet.timestamp;
  els.transitNonce.value = packet.nonce;
  els.transitHmac.textContent = packet.hmac;

  els.transitStatusBadge.textContent = badgeText;
  els.transitStatusBadge.className = `badge ${badgeClass}`;

  els.btnReceiverVerify.disabled = false;
  updateTransitDiff();
}

function updateTransitDiff() {
  if (!activeSenderPacket) return;

  const currentMsg = els.transitMessage.value;
  const currentTs = els.transitTimestamp.value;
  const currentNonce = els.transitNonce.value;

  const isMsgModified = currentMsg !== activeSenderPacket.message;
  const isTsModified = String(currentTs) !== String(activeSenderPacket.timestamp);
  const isNonceModified = currentNonce !== activeSenderPacket.nonce;

  if (isMsgModified || isTsModified || isNonceModified) {
    els.transitStatusBadge.textContent = "TAMPERED IN TRANSIT";
    els.transitStatusBadge.className = "badge danger";
    els.diffIndicator.classList.remove("hidden");

    let diffText = "";
    if (isMsgModified) {
      diffText += `Message: "${activeSenderPacket.message}" ➔ "${currentMsg}" `;
    }
    if (isTsModified) {
      diffText += `Timestamp: ${activeSenderPacket.timestamp} ➔ ${currentTs} `;
    }
    if (isNonceModified) {
      diffText += `Nonce: ${activeSenderPacket.nonce} ➔ ${currentNonce} `;
    }
    els.diffContent.textContent = diffText;
  } else {
    els.transitStatusBadge.textContent = "UNTOUCHED GENUINE";
    els.transitStatusBadge.className = "badge ok";
    els.diffIndicator.classList.add("hidden");
  }
}

/* ---------- Receiver & Security Analysis ---------- */
async function deliverAndVerify(packetToSend, deliveryType) {
  clearSenderError();
  const receiverKey = els.receiverKey.value;
  if (!receiverKey) {
    showSenderError("Receiver secret key cannot be empty.");
    return;
  }

  try {
    const response = await postJSON("/api/replay/verify", {
      message: packetToSend.message,
      key: receiverKey,
      timestamp: packetToSend.timestamp,
      nonce: packetToSend.nonce,
      hmac: packetToSend.hmac,
    });

    renderReceiverAnalysis(response, packetToSend, deliveryType);
  } catch (err) {
    showSenderError("Delivery error: " + err.message);
  }
}

function renderReceiverAnalysis(data, packet, deliveryType) {
  els.receiverAnalysisPanel.classList.remove("hidden");
  els.receiverVerdict.classList.remove("valid", "invalid", "warning");

  const serverCode = data.code || data.reason_code || (data.valid ? "AUTHENTICATED_FRESH" : "REJECTED");
  els.resServerCode.textContent = serverCode;

  // 1. Overall Verdict
  if (data.valid) {
    els.receiverVerdict.classList.add("valid");
    els.receiverVerdictIcon.textContent = "✅";
    els.receiverVerdictTitle.textContent = "Packet ACCEPTED — Message Authentic & Fresh";
    els.receiverVerdictDetail.textContent = data.reason;
    els.resBadgeDecision.className = "badge ok";
    els.resBadgeDecision.textContent = "ACCEPTED";

    // Remember this packet for replay attack demonstration
    lastDeliveredPacket = { ...packet };
    els.btnReplayPacket.disabled = false;

    appendLog(
      "accepted",
      "accepted",
      serverCode,
      `Packet delivered (${deliveryType}). Nonce [${packet.nonce.slice(0, 8)}...] consumed. Receiver verdict: ACCEPTED.`
    );
  } else if (data.code === "REUSED_NONCE" || data.reason_code === "reused_nonce") {
    els.receiverVerdict.classList.add("warning");
    els.receiverVerdictIcon.textContent = "🛡️";
    els.receiverVerdictTitle.textContent = "Replay Attack BLOCKED — Duplicate Nonce Detected";
    els.receiverVerdictDetail.textContent = data.reason;
    els.resBadgeDecision.className = "badge danger";
    els.resBadgeDecision.textContent = "REJECTED (REPLAY)";

    appendLog(
      "replay",
      "replay",
      "REUSED_NONCE",
      `Replay attempt detected for Nonce [${packet.nonce.slice(0, 8)}...]. HMAC tag was mathematically valid, but duplicate packet was rejected!`
    );
  } else if (data.code === "TIMESTAMP_EXPIRED" || data.reason_code === "expired_timestamp") {
    els.receiverVerdict.classList.add("invalid");
    els.receiverVerdictIcon.textContent = "⏳";
    els.receiverVerdictTitle.textContent = "Stale Packet REJECTED — Timestamp Expired";
    els.receiverVerdictDetail.textContent = data.reason;
    els.resBadgeDecision.className = "badge danger";
    els.resBadgeDecision.textContent = "REJECTED (EXPIRED)";

    appendLog(
      "rejected",
      "rejected",
      "TIMESTAMP_EXPIRED",
      `Packet timestamp (${packet.timestamp}) outside ±120s tolerance window. Cryptographic check passed, but packet rejected as stale.`
    );
  } else {
    els.receiverVerdict.classList.add("invalid");
    els.receiverVerdictIcon.textContent = "❌";
    els.receiverVerdictTitle.textContent = "Verification FAILED — Cryptographic Mismatch";
    els.receiverVerdictDetail.textContent = data.reason;
    els.resBadgeDecision.className = "badge danger";
    els.resBadgeDecision.textContent = "REJECTED (TAMPERED)";

    appendLog(
      "rejected",
      "rejected",
      serverCode,
      `Cryptographic verification failed: Tag mismatch (message, timestamp, or nonce was tampered with, or key mismatch).`
    );
  }

  // 2. A. Cryptographic Check Breakdown
  els.resBadgeCrypto.className = "badge " + (data.crypto_valid ? "ok" : "danger");
  els.resBadgeCrypto.textContent = data.crypto_valid ? "PASS (MATCH)" : "FAIL (MISMATCH)";
  els.resTagReceived.textContent = data.received_hmac_short || packet.hmac.slice(0, 8) + "...";
  els.resTagExpected.textContent = data.expected_hmac_short || "N/A";

  // 3. B. Timestamp Freshness Breakdown
  if (!data.crypto_valid) {
    els.resBadgeFreshness.className = "badge";
    els.resBadgeFreshness.textContent = "UNCHECKED";
    els.resFreshnessDetail.textContent = "Skipped (failed cryptographic check)";
  } else if (data.code === "TIMESTAMP_EXPIRED" || data.reason_code === "expired_timestamp") {
    els.resBadgeFreshness.className = "badge danger";
    els.resBadgeFreshness.textContent = "EXPIRED (STALE)";
    els.resFreshnessDetail.textContent = "Timestamp outside ±120s tolerance window";
  } else if (data.code === "FUTURE_TIMESTAMP") {
    els.resBadgeFreshness.className = "badge danger";
    els.resBadgeFreshness.textContent = "FUTURE SKEW";
    els.resFreshnessDetail.textContent = "Timestamp too far in the future";
  } else {
    els.resBadgeFreshness.className = "badge ok";
    els.resBadgeFreshness.textContent = "FRESH (VALID)";
    els.resFreshnessDetail.textContent = "Within allowable ±120s tolerance window";
  }

  // 4. C. Nonce Uniqueness Breakdown
  if (!data.crypto_valid || data.code === "TIMESTAMP_EXPIRED" || data.reason_code === "expired_timestamp") {
    els.resBadgeNonce.className = "badge";
    els.resBadgeNonce.textContent = "UNCHECKED";
    els.resNonceDetail.textContent = "Not evaluated (cache untouched to prevent poisoning)";
  } else if (data.code === "REUSED_NONCE" || data.reason_code === "reused_nonce") {
    els.resBadgeNonce.className = "badge danger";
    els.resBadgeNonce.textContent = "REUSED (BLOCKED)";
    els.resNonceDetail.textContent = "Nonce already consumed in receiver memory";
  } else {
    els.resBadgeNonce.className = "badge ok";
    els.resBadgeNonce.textContent = "UNIQUE (CONSUMED)";
    els.resNonceDetail.textContent = "First presentation; nonce now recorded in cache";
  }
}

/* ================================================================
   EVENT LISTENERS
   ================================================================ */

// Stage 1: Sender creates fresh packet
els.btnCreatePacket.addEventListener("click", async () => {
  clearSenderError();
  const message = els.senderMessage.value.trim();
  const key = els.senderKey.value;

  if (!message) return showSenderError("Please enter a message to authenticate.");
  if (!key) return showSenderError("Secret key must not be empty.");

  try {
    const packet = await postJSON("/api/replay/sign", { message, key });
    activeSenderPacket = packet;

    renderSenderPacket(packet);
    loadPacketIntoTransit(packet, "UNTOUCHED GENUINE", "ok");

    appendLog(
      "system",
      "info",
      "PACKET_CREATED",
      `Sender generated packet: Nonce [${packet.nonce.slice(0, 8)}...], Timestamp [${packet.timestamp}]. Ready on network.`
    );
  } catch (err) {
    showSenderError(err.message);
  }
});

// Stage 1: Sender simulates educational stale packet
els.btnCreateStale.addEventListener("click", async () => {
  clearSenderError();
  const message = els.senderMessage.value.trim();
  const key = els.senderKey.value;

  if (!message) return showSenderError("Please enter a message to authenticate.");
  if (!key) return showSenderError("Secret key must not be empty.");

  try {
    const packet = await postJSON("/api/replay/simulate-stale", {
      message,
      key,
      age_seconds: 180.0,
    });
    activeSenderPacket = packet;

    renderSenderPacket(packet);
    loadPacketIntoTransit(packet, "STALE PACKET (3m old)", "warning");

    appendLog(
      "system",
      "info",
      "STALE_CREATED",
      `Simulated stale packet fixture generated: Timestamp [${packet.timestamp}] (~3 mins ago). Genuine HMAC tag created for past timestamp.`
    );
  } catch (err) {
    showSenderError(err.message);
  }
});

// Stage 2: Deliver unmodified packet
els.btnDeliverNormal.addEventListener("click", () => {
  if (!activeSenderPacket) return;

  // Restore untouched original into transit
  loadPacketIntoTransit(activeSenderPacket, "UNTOUCHED GENUINE", "ok");
  deliverAndVerify(activeSenderPacket, "Normal Delivery");
});

// Stage 2: Tamper with message
els.btnTamperMsg.addEventListener("click", () => {
  if (!activeSenderPacket) return;

  const currentMsg = els.transitMessage.value;
  let tamperedText;
  if (currentMsg.endsWith(" [TAMPERED]")) {
    tamperedText = currentMsg + "!";
  } else {
    tamperedText = currentMsg + " [TAMPERED]";
  }

  els.transitMessage.value = tamperedText;
  updateTransitDiff();

  const tamperedPacket = {
    message: tamperedText,
    timestamp: els.transitTimestamp.value,
    nonce: els.transitNonce.value,
    hmac: els.transitHmac.textContent, // Strictly preserves sender's original tag!
  };

  deliverAndVerify(tamperedPacket, "Tampered Message");
});

// Stage 2: Replay captured packet
els.btnReplayPacket.addEventListener("click", () => {
  if (!lastDeliveredPacket) return;

  // Reload the captured packet into transit
  loadPacketIntoTransit(lastDeliveredPacket, "CAPTURED REPLAY", "warning");

  appendLog(
    "replay",
    "replay",
    "REPLAY_TRANSMIT",
    `Attacker resending captured packet with Nonce [${lastDeliveredPacket.nonce.slice(0, 8)}...] and original HMAC tag...`
  );

  deliverAndVerify(lastDeliveredPacket, "Replay Attack");
});

// Stage 2: Deliver custom in-transit edits
els.btnDeliverCustom.addEventListener("click", () => {
  const customPacket = {
    message: els.transitMessage.value.trim(),
    timestamp: els.transitTimestamp.value.trim(),
    nonce: els.transitNonce.value.trim(),
    hmac: els.transitHmac.textContent.trim(),
  };

  if (!customPacket.message || !customPacket.timestamp || !customPacket.nonce) {
    showSenderError("All in-transit packet fields must be populated.");
    return;
  }

  deliverAndVerify(customPacket, "Custom In-Transit Delivery");
});

// Dynamic diff detection as user types in transit message
els.transitMessage.addEventListener("input", updateTransitDiff);
els.transitTimestamp.addEventListener("input", updateTransitDiff);
els.transitNonce.addEventListener("input", updateTransitDiff);

// Stage 3: Receiver Verify button
els.btnReceiverVerify.addEventListener("click", () => {
  const currentPacket = {
    message: els.transitMessage.value.trim(),
    timestamp: els.transitTimestamp.value.trim(),
    nonce: els.transitNonce.value.trim(),
    hmac: els.transitHmac.textContent.trim(),
  };
  deliverAndVerify(currentPacket, "Manual Receiver Check");
});

// Stage 4: Reset Nonce Cache
els.btnResetNonceCache.addEventListener("click", async () => {
  try {
    const data = await postJSON("/api/replay/reset", {});
    lastDeliveredPacket = null;
    els.btnReplayPacket.disabled = true;

    appendLog(
      "system",
      "info",
      "CACHE_RESET",
      `Receiver in-memory nonce cache cleared (tracked count reset to ${data.cached_count}). Ready for fresh trials.`
    );
  } catch (err) {
    showSenderError("Error clearing cache: " + err.message);
  }
});

// Stage 4: Clear Log
els.btnClearLog.addEventListener("click", () => {
  els.logContainer.innerHTML = "";
  appendLog("system", "info", "READY", "Event log cleared. Lab ready.");
});

// Stage 1: Reset All
els.btnSenderReset.addEventListener("click", () => {
  els.senderMessage.value = "Transfer 250 units to account 9821";
  els.senderKey.value = "shared-secret-key";
  els.receiverKey.value = "shared-secret-key";

  activeSenderPacket = null;
  lastDeliveredPacket = null;

  els.senderPacketView.classList.add("hidden");
  els.networkPacketPanel.classList.add("hidden");
  els.networkEmptyNotice.classList.remove("hidden");
  els.receiverAnalysisPanel.classList.add("hidden");
  els.btnReceiverVerify.disabled = true;
  els.btnReplayPacket.disabled = true;

  clearSenderError();
  appendLog("system", "info", "RESET", "Laboratory reset to default state.");
});

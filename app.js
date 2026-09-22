// app.js -- CertiChain, fully client-side. No backend required.
// Persistence: browser localStorage (per-browser, per-device).
// Hashing: Web Crypto SubtleCrypto (SHA-256).

// ---------------------------------------------------------------
// Hashing helpers (mirrors the reference Python hashing.py exactly)
// ---------------------------------------------------------------
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashCertificate(cert) {
  const payload = {
    recipient_name: (cert.recipient_name || "").trim(),
    course_name: (cert.course_name || "").trim(),
    institution: (cert.institution || "").trim(),
    issue_date: (cert.issue_date || "").trim(),
    certificate_id: (cert.certificate_id || "").trim(),
  };
  const keys = Object.keys(payload).sort();
  const canonical = "{" + keys.map((k) => JSON.stringify(k) + ":" + JSON.stringify(payload[k])).join(",") + "}";
  return sha256Hex(canonical);
}

async function hashBlock(index, timestamp, dataHash, prevHash) {
  return sha256Hex(`${index}|${timestamp}|${dataHash}|${prevHash}`);
}

const GENESIS_HASH = "0".repeat(64);

function genCertId() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = "";
  for (let i = 0; i < 8; i++) s += alphabet[Math.floor(Math.random() * alphabet.length)];
  return "CERT-" + s;
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str ?? "";
  return d.innerHTML;
}

function fmtBool(v) {
  return v === null || v === undefined ? "—" : v ? "Yes" : "No";
}

// ---------------------------------------------------------------
// Storage layer: localStorage, two keys holding JSON blobs.
// Kept behind small async-shaped functions so the rest of the app
// doesn't care whether storage is sync (localStorage) or async
// (a future real backend).
// ---------------------------------------------------------------
const CERTS_KEY = "certichain_certificates_v1";
const LEDGER_KEY = "certichain_ledger_v1";

function readStore(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch (e) {
    console.error("CertiChain storage read failed:", e);
    return fallback;
  }
}

function writeStore(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    console.error("CertiChain storage write failed:", e);
    alert("Could not save to browser storage (it may be full or disabled).");
  }
}

async function certGet(certificateId) {
  const certs = readStore(CERTS_KEY, {});
  return certs[certificateId] || null;
}
async function certSet(certificateId, data) {
  const certs = readStore(CERTS_KEY, {});
  certs[certificateId] = data;
  writeStore(CERTS_KEY, certs);
}
async function certUpdate(certificateId, patch) {
  const certs = readStore(CERTS_KEY, {});
  certs[certificateId] = { ...certs[certificateId], ...patch };
  writeStore(CERTS_KEY, certs);
}
async function certList() {
  const certs = readStore(CERTS_KEY, {});
  return Object.values(certs);
}

async function ledgerGetLast() {
  const ledger = readStore(LEDGER_KEY, []);
  return ledger.length ? ledger[ledger.length - 1] : null;
}
async function ledgerAddBlock(block) {
  const ledger = readStore(LEDGER_KEY, []);
  ledger.push(block);
  writeStore(LEDGER_KEY, ledger);
}
async function ledgerList() {
  return readStore(LEDGER_KEY, []);
}
async function ledgerGetBlockForCert(certificateId) {
  const all = await ledgerList();
  return all.find((b) => b.certificate_id === certificateId) || null;
}

// ---------------------------------------------------------------
// Core logic (ports of the reference ledger.py / fraud.py)
// ---------------------------------------------------------------
async function addBlock(certificateId, dataHash) {
  const last = await ledgerGetLast();
  const index = last ? last.block_index + 1 : 0;
  const prevHash = last ? last.block_hash : GENESIS_HASH;
  const timestamp = new Date().toISOString();
  const blockHash = await hashBlock(index, timestamp, dataHash, prevHash);
  const block = {
    block_index: index,
    certificate_id: certificateId,
    data_hash: dataHash,
    prev_hash: prevHash,
    block_hash: blockHash,
    timestamp,
  };
  await ledgerAddBlock(block);
  return block;
}

async function verifyChain() {
  const blocks = await ledgerList();
  let expectedPrev = GENESIS_HASH;
  for (const block of blocks) {
    const recomputed = await hashBlock(block.block_index, block.timestamp, block.data_hash, block.prev_hash);
    if (block.prev_hash !== expectedPrev) {
      return {
        valid: false,
        total_blocks: blocks.length,
        broken_at: block.block_index,
        reason: "prev_hash pointer does not match the preceding block",
      };
    }
    if (recomputed !== block.block_hash) {
      return {
        valid: false,
        total_blocks: blocks.length,
        broken_at: block.block_index,
        reason: "block hash does not match its stored data (possible tampering)",
      };
    }
    expectedPrev = block.block_hash;
  }
  return { valid: true, total_blocks: blocks.length, broken_at: null, reason: null };
}

async function checkCertificate(certificateId) {
  const details = [];
  const record = await certGet(certificateId);

  if (!record) {
    const chain = await verifyChain();
    return {
      certificate_id: certificateId,
      exists: false,
      revoked: false,
      hash_matches: null,
      ledger_entry_found: false,
      ledger_hash_matches: null,
      chain_valid: chain.valid,
      verdict: "not_found",
      details: ["No certificate with this ID exists."],
    };
  }

  const recomputedHash = await hashCertificate(record);
  const hashMatches = recomputedHash === record.data_hash;
  if (!hashMatches) {
    details.push(
      "Stored certificate fields do not match the original recorded hash -- the record may have been edited after issuance."
    );
  }

  const block = await ledgerGetBlockForCert(certificateId);
  const ledgerFound = !!block;
  let ledgerHashMatches = null;
  if (ledgerFound) {
    ledgerHashMatches = block.data_hash === record.data_hash;
    if (!ledgerHashMatches) {
      details.push("The certificate's current hash does not match the hash recorded in the ledger at issuance time.");
    }
  } else {
    details.push("No ledger entry found for this certificate ID.");
  }

  const chain = await verifyChain();
  if (!chain.valid) {
    details.push(`The overall ledger chain is broken at block ${chain.broken_at} (${chain.reason}).`);
  }

  let verdict;
  if (record.revoked) {
    verdict = "revoked";
    details.push("This certificate has been explicitly revoked by the issuer.");
  } else if (!hashMatches || !ledgerHashMatches || !chain.valid) {
    verdict = "tampered";
  } else {
    verdict = "genuine";
    details.push("Certificate data matches the ledger and the chain is intact.");
  }

  return {
    certificate_id: certificateId,
    exists: true,
    revoked: !!record.revoked,
    hash_matches: hashMatches,
    ledger_entry_found: ledgerFound,
    ledger_hash_matches: ledgerHashMatches,
    chain_valid: chain.valid,
    verdict,
    details,
  };
}

// ---------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");

    if (btn.dataset.tab === "registry") loadRegistry();
    if (btn.dataset.tab === "ledger") loadLedger();
    if (btn.dataset.tab !== "scan") stopScanning();
  });
});

// ---------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------
function verdictBadge(verdict) {
  const labels = {
    genuine: "Genuine",
    tampered: "Tampered / Mismatch",
    revoked: "Revoked",
    not_found: "Not Found",
  };
  return `<span class="verdict ${verdict}">${labels[verdict] || verdict}</span>`;
}

function renderVerifyReport(report) {
  const details = (report.details || []).map((d) => `<li>${escapeHtml(d)}</li>`).join("");
  return `
    <h3 style="margin-top:0;">Certificate: ${escapeHtml(report.certificate_id)} ${verdictBadge(report.verdict)}</h3>
    <div class="result-grid">
      <div><span class="label">Exists in storage</span>${report.exists ? "Yes" : "No"}</div>
      <div><span class="label">Revoked</span>${report.revoked ? "Yes" : "No"}</div>
      <div><span class="label">Data hash matches record</span>${fmtBool(report.hash_matches)}</div>
      <div><span class="label">Found in ledger</span>${report.ledger_entry_found ? "Yes" : "No"}</div>
      <div><span class="label">Ledger hash matches</span>${fmtBool(report.ledger_hash_matches)}</div>
      <div><span class="label">Overall chain valid</span>${fmtBool(report.chain_valid)}</div>
    </div>
    <ul class="detail-list">${details}</ul>
  `;
}

// ---------------------------------------------------------------
// Issue
// ---------------------------------------------------------------
const issueForm = document.getElementById("issue-form");
issueForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = issueForm.querySelector("button");
  btn.disabled = true;
  btn.textContent = "Issuing…";

  try {
    const formData = new FormData(issueForm);
    const payload = Object.fromEntries(formData.entries());
    for (const [k, v] of Object.entries(payload)) payload[k] = (v || "").trim();

    let certificateId = genCertId();
    while (await certGet(certificateId)) certificateId = genCertId();

    const dataHash = await hashCertificate({ ...payload, certificate_id: certificateId });
    const record = {
      certificate_id: certificateId,
      recipient_name: payload.recipient_name,
      course_name: payload.course_name,
      institution: payload.institution,
      issue_date: payload.issue_date,
      data_hash: dataHash,
      created_at: new Date().toISOString(),
      revoked: false,
    };
    await certSet(certificateId, record);
    await addBlock(certificateId, dataHash);

    const detailsBox = document.getElementById("issue-details");
    detailsBox.innerHTML = `
      <div><span class="label">Certificate ID</span>${escapeHtml(certificateId)}</div>
      <div><span class="label">Recipient</span>${escapeHtml(record.recipient_name)}</div>
      <div><span class="label">Course</span>${escapeHtml(record.course_name)}</div>
      <div><span class="label">Institution</span>${escapeHtml(record.institution)}</div>
      <div><span class="label">Issue Date</span>${escapeHtml(record.issue_date)}</div>
      <div><span class="label">Data Hash</span><span class="mono">${escapeHtml(dataHash)}</span></div>
    `;

    const qrDiv = document.getElementById("issue-qr");
    qrDiv.innerHTML = "";
    if (window.QRCode) {
      new QRCode(qrDiv, {
        text: JSON.stringify({ certificate_id: certificateId, data_hash: dataHash }),
        width: 200,
        height: 200,
        correctLevel: QRCode.CorrectLevel.M,
      });
    } else {
      qrDiv.textContent = "QR library failed to load (check your internet connection).";
    }

    document.getElementById("issue-result").classList.remove("hidden");
    issueForm.reset();
  } catch (err) {
    alert("Could not issue certificate: " + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Issue Certificate";
  }
});

// ---------------------------------------------------------------
// Verify by ID
// ---------------------------------------------------------------
document.getElementById("verify-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = document.getElementById("verify-id-input").value.trim();
  if (!id) return;

  const box = document.getElementById("verify-result");
  box.classList.remove("hidden");
  box.innerHTML = "Checking…";
  const report = await checkCertificate(id);
  box.innerHTML = renderVerifyReport(report);
});

// ---------------------------------------------------------------
// Scan QR
// ---------------------------------------------------------------
let scanStream = null;
let scanRAF = null;

const video = document.getElementById("scan-video");
const canvas = document.getElementById("scan-canvas");
const ctx = canvas.getContext("2d", { willReadFrequently: true });

document.getElementById("start-scan").addEventListener("click", startScanning);
document.getElementById("stop-scan").addEventListener("click", stopScanning);

async function startScanning() {
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch (err) {
    alert("Could not access camera: " + err.message);
    return;
  }
  video.srcObject = scanStream;
  video.classList.remove("hidden");
  await video.play();

  document.getElementById("start-scan").classList.add("hidden");
  document.getElementById("stop-scan").classList.remove("hidden");

  scanLoop();
}

function stopScanning() {
  if (scanRAF) cancelAnimationFrame(scanRAF);
  scanRAF = null;
  if (scanStream) {
    scanStream.getTracks().forEach((t) => t.stop());
    scanStream = null;
  }
  video.classList.add("hidden");
  document.getElementById("start-scan").classList.remove("hidden");
  document.getElementById("stop-scan").classList.add("hidden");
}

function scanLoop() {
  if (!scanStream) return;

  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    const code = window.jsQR ? window.jsQR(imageData.data, imageData.width, imageData.height) : null;
    if (code && code.data) {
      handleScannedText(code.data);
      stopScanning();
      return;
    }
  }
  scanRAF = requestAnimationFrame(scanLoop);
}

async function handleScannedText(rawText) {
  let certificateId = null;
  let scannedHash = null;
  try {
    const decoded = JSON.parse(rawText);
    certificateId = decoded.certificate_id;
    scannedHash = decoded.data_hash;
  } catch (e) {
    certificateId = rawText.trim();
  }

  const box = document.getElementById("scan-result");
  box.classList.remove("hidden");
  box.innerHTML = "Checking…";

  if (!certificateId) {
    box.innerHTML = "<p>Could not read a certificate ID from that QR code.</p>";
    return;
  }

  const report = await checkCertificate(certificateId);
  if (report.exists && scannedHash) {
    const record = await certGet(certificateId);
    if (record && scannedHash !== record.data_hash) {
      report.verdict = "tampered";
      report.details.push("The hash encoded in the scanned QR code does not match the certificate's stored hash.");
    }
  }
  box.innerHTML = renderVerifyReport(report);
}

// ---------------------------------------------------------------
// Registry
// ---------------------------------------------------------------
document.getElementById("refresh-registry").addEventListener("click", loadRegistry);

async function loadRegistry() {
  const certs = await certList();
  certs.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));

  const tbody = document.querySelector("#registry-table tbody");
  tbody.innerHTML = "";
  document.getElementById("registry-empty").classList.toggle("hidden", certs.length > 0);

  certs.forEach((cert) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(cert.certificate_id)}</td>
      <td>${escapeHtml(cert.recipient_name)}</td>
      <td>${escapeHtml(cert.course_name)}</td>
      <td>${escapeHtml(cert.institution)}</td>
      <td>${escapeHtml(cert.issue_date)}</td>
      <td>${cert.revoked ? verdictBadge("revoked") : verdictBadge("genuine")}</td>
      <td>${cert.revoked ? "" : `<button data-id="${escapeHtml(cert.certificate_id)}" class="btn-secondary revoke-btn">Revoke</button>`}</td>
    `;
    tbody.appendChild(tr);
  });

  document.querySelectorAll(".revoke-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Revoke certificate ${btn.dataset.id}?`)) return;
      await certUpdate(btn.dataset.id, { revoked: true });
      loadRegistry();
    });
  });
}

// ---------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------
document.getElementById("check-chain").addEventListener("click", async () => {
  const box = document.getElementById("chain-status");
  box.classList.remove("hidden");
  box.innerHTML = "Checking…";
  const data = await verifyChain();
  box.innerHTML = `
    <strong>${data.valid ? "✅ Chain is intact" : "⚠️ Chain integrity FAILED"}</strong>
    <p>Total blocks: ${data.total_blocks}</p>
    ${!data.valid ? `<p>Broken at block ${data.broken_at}: ${escapeHtml(data.reason)}</p>` : ""}
  `;
});

async function loadLedger() {
  const blocks = await ledgerList();
  const tbody = document.querySelector("#ledger-table tbody");
  tbody.innerHTML = "";
  document.getElementById("ledger-empty").classList.toggle("hidden", blocks.length > 0);

  blocks.forEach((block) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${block.block_index}</td>
      <td>${escapeHtml(block.certificate_id)}</td>
      <td class="mono">${escapeHtml(block.data_hash.slice(0, 16))}…</td>
      <td class="mono">${escapeHtml(block.prev_hash.slice(0, 16))}…</td>
      <td class="mono">${escapeHtml(block.block_hash.slice(0, 16))}…</td>
      <td>${escapeHtml(block.timestamp)}</td>
    `;
    tbody.appendChild(tr);
  });
}

import { generateArtifacts, presets, validDNS } from "./crypto.bundle.js";

(() => {
  const filenames = { config: "csr.conf" };
  const byId = (id) => document.getElementById(id);
  const inHub = location.pathname.startsWith("/modules/");
  if (inHub) {
    const sharedStyles = document.createElement("link");
    sharedStyles.rel = "stylesheet"; sharedStyles.href = "/static/styles.css";
    document.head.insertBefore(sharedStyles, byId("csr-styles"));
  }
  const form = byId("generator");
  let artifacts = null;
  let pending = null;
  let feedbackTimer;
  let expirationTimer;
  let theme = "modern";
  try { theme = localStorage.getItem("lsz_theme") || "modern"; } catch {}
  document.documentElement.dataset.theme = theme;

  byId("theme").addEventListener("click", () => {
    theme = theme === "terminal" ? "modern" : "terminal";
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("lsz_theme", theme); } catch {}
  });

  function showError(message) {
    byId("error").textContent = message;
    byId("error").hidden = !message;
  }

  function announce(message) {
    clearTimeout(feedbackTimer);
    byId("feedback").textContent = message;
    feedbackTimer = setTimeout(() => { byId("feedback").textContent = ""; }, 5000);
  }

  function clearArtifacts() {
    clearTimeout(expirationTimer);
    artifacts = null;
    byId("key-output").value = "";
    byId("csr-output").value = "";
    byId("verification-output").value = "";
    byId("config-output").replaceChildren();
    byId("results").hidden = true;
  }

  function busy(value) {
    form.setAttribute("aria-busy", String(value));
    for (const control of form.elements) control.disabled = value;
    byId("spinner").hidden = !value;
    byId("generate-label").textContent = value ? "Wird erstellt ..." : "Schluessel & CSR erstellen";
  }

  function addSAN(value = "", focus = false) {
    if (byId("sans").children.length >= 100) { showError("Maximal 100 DNS-Namen sind erlaubt."); return; }
    const row = document.createElement("div");
    row.className = "san-row";
    const input = document.createElement("input");
    input.value = value; input.required = true; input.maxLength = 253;
    input.spellcheck = false; input.autocapitalize = "none";
    input.setAttribute("aria-label", "Alternativer DNS-Name");
    const remove = document.createElement("button");
    remove.type = "button"; remove.className = "ghost icon-button"; remove.textContent = "×";
    remove.title = "DNS-Name entfernen"; remove.setAttribute("aria-label", "DNS-Name entfernen");
    remove.addEventListener("click", () => { row.remove(); clearArtifacts(); });
    row.append(input, remove); byId("sans").appendChild(row);
    if (focus) input.focus();
  }

  function applyStage() {
    clearArtifacts(); showError("");
    const names = presets[byId("stage").value];
    byId("cn").value = names[0];
    byId("sans").replaceChildren(); names.forEach((name) => addSAN(name));
  }

  function highlightConfig(config) {
    const output = byId("config-output");
    output.replaceChildren();
    for (const line of config.split("\n")) {
      if (line.startsWith("[")) {
        const section = document.createElement("span"); section.className = "syntax-section"; section.textContent = line; output.append(section);
      } else if (line.includes("=")) {
        const split = line.indexOf("=");
        const key = document.createElement("span"); key.className = "syntax-key"; key.textContent = line.slice(0, split);
        output.append(key, document.createTextNode(line.slice(split)));
      } else { output.append(document.createTextNode(line)); }
      output.append(document.createTextNode("\n"));
    }
  }

  byId("stage").addEventListener("change", applyStage);
  byId("add-san").addEventListener("click", () => { addSAN("", true); clearArtifacts(); });
  form.addEventListener("input", clearArtifacts);
  byId("bits").addEventListener("change", clearArtifacts);
  byId("clear").addEventListener("click", () => { clearArtifacts(); announce("Ausgaben verworfen."); });

  form.addEventListener("submit", async (event) => {
    event.preventDefault(); showError(""); clearArtifacts();
    const cn = byId("cn").value.trim();
    const sans = Array.from(byId("sans").querySelectorAll("input"), (input) => input.value.trim());
    if (!validDNS(cn) || sans.length === 0 || !sans.every(validDNS)) { showError("Bitte gueltige DNS-Namen ohne Leerzeichen, Wildcards oder Protokoll angeben."); return; }
    if (new Set(sans.map((name) => name.toLowerCase())).size !== sans.length) { showError("DNS-Namen duerfen nicht doppelt vorkommen."); return; }
    if (!sans.some((name) => name.toLowerCase() === cn.toLowerCase())) { showError("Bitte den Common Name auch als alternativen DNS-Namen aufnehmen."); return; }
    const payload = { stage: byId("stage").value, bits: Number(byId("bits").value), cn, sans };
    const createdAt = new Date();
    const basename = `BNET2_${payload.stage}_${createdAt.getMonth() + 1}_${createdAt.getFullYear()}`;
    const job = {}; pending = job;
    busy(true);
    try {
      const result = await generateArtifacts(payload);
      if (pending !== job) return;
      artifacts = result;
      filenames.key = `${basename}.key`;
      filenames.csr = `${basename}.csr`;
      for (const button of byId("results").querySelectorAll('button[data-action="download"]')) {
        button.title = `${filenames[button.dataset.artifact]} herunterladen`;
      }
      byId("key-output").value = result.key;
      byId("csr-output").value = result.csr;
      byId("verification-output").value = result.verification;
      highlightConfig(result.config);
      byId("results").hidden = false;
      announce("Neuer Schluessel und CSR wurden erstellt.");
      expirationTimer = setTimeout(() => { clearArtifacts(); announce("Ausgaben nach 15 Minuten verworfen."); }, 15 * 60 * 1000);
    } catch (error) {
      if (pending !== job) return;
      showError(error.message || "Schluessel und CSR konnten nicht erstellt werden. Bitte einen aktuellen Browser verwenden.");
    } finally {
      if (pending === job) { pending = null; busy(false); }
    }
  });

  byId("results").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button || !artifacts) return;
    const name = button.dataset.artifact;
    const content = artifacts[name];
    if (button.dataset.action === "copy") {
      try {
        await navigator.clipboard.writeText(content);
        button.classList.add("copied");
        setTimeout(() => button.classList.remove("copied"), 1800);
        announce(`${filenames[name]} in die Zwischenablage kopiert.`);
      } catch { showError("Zwischenablage nicht verfuegbar. Bitte den Text markieren und manuell kopieren."); }
    } else {
      const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
      const link = document.createElement("a"); link.href = url; link.download = filenames[name];
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      announce(`${filenames[name]} zum Download uebergeben.`);
    }
  });

  window.addEventListener("pagehide", () => { pending = null; clearArtifacts(); });
  window.addEventListener("pageshow", (event) => { if (event.persisted) { clearArtifacts(); busy(false); } });
  applyStage();
  const supported = Boolean(globalThis.crypto?.subtle);
  byId("crypto-status").textContent = supported ? "Lokal im Browser" : "Kryptografie nicht verfuegbar";
  if (!supported) {
    byId("generate").disabled = true;
    showError("Bitte einen aktuellen Browser verwenden und den Hub ueber localhost, 127.0.0.1 oder HTTPS oeffnen.");
  }
})();
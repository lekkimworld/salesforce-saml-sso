import {parseStringPromise} from "xml2js";
import express from "express";
import { AssertionInput, buildAssertionInfo, cleanupPEMCertificate, verifyAuthnRequest } from "./saml-utils";
import { getConfig, setConfig, applyPreset, getPresets, AmrAcrConfig } from "./amr-config";
import { config as dotenv_config } from "dotenv";
dotenv_config();

// store debug data
let lastAuthnRequestXml : string | undefined;
let lastAuthnRequestJson: string | undefined;
let lastResponseXml: string | undefined;

declare global {
    namespace NodeJS {
        interface ProcessEnv {
            SAML_PRIVATE_KEY: string;
            SAML_CERTIFICATE: string;
            SAML_LOGIN_URL: string;
            SAML_ISSUER: string;
            SAML_ENTITY_ID: string;
            FEDERATION_ID?: string;
        }
    }
}

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/debug/last/:data/:type", (req, res) => {
    if (req.params.data === "authn") {
        if (req.params.type === "xml") {
            res.type("xml").send(lastAuthnRequestXml);
        } else {
            res.type("json").send(lastAuthnRequestJson);
        }
    } else if (req.params.data === "response") {
        res.type("xml").send(lastResponseXml);
    } else {
        res.status(417).send("Expected type to be authn or response");
    }
});

app.get("/admin/config", (_req, res) => {
    res.json({ config: getConfig(), presets: getPresets() });
});

app.post("/admin/config", (req, res) => {
    const body = req.body;
    if (body.presetId) {
        try {
            const config = applyPreset(body.presetId);
            return res.json({ config });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    }
    const config: AmrAcrConfig = {
        includeAcr: body.includeAcr !== false,
        includeAmr: !!body.includeAmr,
        amrValues: Array.isArray(body.amrValues) ? body.amrValues : [],
        authnContextClassRef: body.authnContextClassRef || "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
        activePreset: body.activePreset || "custom",
    };
    setConfig(config);
    res.json({ config: getConfig() });
});

app.post("/admin/generate", (req, res) => {
    const federationId = req.body.federationId;
    if (!federationId || federationId.indexOf("@") < 0) {
        return res.status(400).json({ error: "Invalid federation ID" });
    }
    const amrConfig = getConfig();
    const options: AssertionInput = {
        federationId,
        assertionConsumerServiceUrl: process.env.SAML_LOGIN_URL,
        key: Buffer.from(process.env.SAML_PRIVATE_KEY, "base64"),
        cert: cleanupPEMCertificate(Buffer.from(process.env.SAML_CERTIFICATE, "base64").toString()),
        issuer: process.env.SAML_ISSUER,
        entityId: process.env.SAML_ENTITY_ID,
        includeAcr: amrConfig.includeAcr,
        authnContextClassRef: amrConfig.authnContextClassRef,
        amrValues: amrConfig.includeAmr ? amrConfig.amrValues : undefined,
    };
    const responseOutput = buildAssertionInfo(options);
    lastResponseXml = responseOutput.signedResponse;
    res.json({ success: true });
});

app.get("/admin", (_req, res) => {
    const presetsJson = JSON.stringify(getPresets());
    res.type("html").send(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SAML IdP - AMR/ACR Configuration</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; }
  h1 { color: #333; }
  .card { background: white; border-radius: 8px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  label { display: block; font-weight: 600; margin-bottom: 6px; color: #555; }
  select, input[type="text"], textarea { width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
  textarea { font-family: monospace; resize: vertical; }
  .checkbox-row { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; }
  .checkbox-row label { display: inline; margin-bottom: 0; }
  button { background: #0070d2; color: white; border: none; padding: 10px 20px; border-radius: 4px; font-size: 14px; cursor: pointer; }
  button:hover { background: #005bb5; }
  .preset-desc { font-size: 13px; color: #666; margin-top: 4px; font-style: italic; }
  .status { padding: 8px 12px; border-radius: 4px; margin-top: 12px; display: none; }
  .status.success { display: block; background: #d4edda; color: #155724; }
  .status.error { display: block; background: #f8d7da; color: #721c24; }
  pre { background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 4px; overflow-x: auto; font-size: 13px; white-space: pre-wrap; }
  .mfa-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: 600; margin-left: 8px; }
  .mfa-badge.sufficient { background: #d4edda; color: #155724; }
  .mfa-badge.insufficient { background: #f8d7da; color: #721c24; }
  .mfa-badge.phishing-resistant { background: #cce5ff; color: #004085; }
</style>
</head>
<body>
<h1>SAML IdP - AMR/ACR Configuration</h1>

<div class="card">
  <label for="preset">Preset Scenario</label>
  <select id="preset"></select>
  <div class="preset-desc" id="preset-desc"></div>
</div>

<div class="card">
  <div class="checkbox-row">
    <input type="checkbox" id="includeAcr" checked>
    <label for="includeAcr">Include AuthnContextClassRef</label>
  </div>

  <label for="acr">AuthnContextClassRef</label>
  <input type="text" id="acr" placeholder="urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified">

  <div class="checkbox-row" style="margin-top: 16px;">
    <input type="checkbox" id="includeAmr">
    <label for="includeAmr">Include AMR Attribute (http://schemas.microsoft.com/claims/authnmethodsreferences)</label>
  </div>

  <label for="amrValues">AMR Values (one per line)</label>
  <textarea id="amrValues" rows="3" placeholder="pwd&#10;fido2"></textarea>
</div>

<div class="card">
  <button onclick="saveConfig()">Save Configuration</button>
  <div class="status" id="status"></div>
</div>

<div class="card">
  <label for="federationId">IdP-Initiated Login</label>
  <div style="display: flex; gap: 8px;">
    <input type="text" id="federationId" value="${process.env.FEDERATION_ID || 'tom.brady@example.com'}" placeholder="tom.brady@example.com">
    <button onclick="initiateLogin()" style="white-space: nowrap;">Login</button>
    <button onclick="generateOnly()" style="white-space: nowrap;">Generate Only</button>
  </div>
</div>

<div class="card">
  <label>Debug Links</label>
  <p style="margin: 4px 0;">
    <a href="/debug/last/response/xml" target="_blank">Last SAML Response (XML)</a>
    <button onclick="copyDebugContent('/debug/last/response/xml')" style="padding: 2px 8px; font-size: 11px; margin-left: 4px;">Copy</button>
  </p>
  <p style="margin: 4px 0;">
    <a href="/debug/last/authn/xml" target="_blank">Last AuthnRequest (XML)</a>
    <button onclick="copyDebugContent('/debug/last/authn/xml')" style="padding: 2px 8px; font-size: 11px; margin-left: 4px;">Copy</button>
  </p>
  <p style="margin: 4px 0;">
    <a href="/debug/last/authn/json" target="_blank">Last AuthnRequest (JSON)</a>
    <button onclick="copyDebugContent('/debug/last/authn/json')" style="padding: 2px 8px; font-size: 11px; margin-left: 4px;">Copy</button>
  </p>
  <p style="margin: 4px 0;">
    <a href="${process.env.SAML_LOGIN_URL ? process.env.SAML_LOGIN_URL.replace(/\.my\.salesforce\.com.*/, '.my.salesforce-setup.com/lightning/setup/SingleSignOn/home') : '#'}" target="_blank">Salesforce SSO Setup</a>
  </p>
  <div class="status" id="debug-status"></div>
</div>

<div class="card">
  <label>XML Preview (AuthnStatement + AttributeStatement)</label>
  <pre id="preview"></pre>
</div>

<script>
const presets = ${presetsJson};

function init() {
  const select = document.getElementById("preset");
  presets.forEach(p => {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.textContent = p.name;
    select.appendChild(opt);
  });
  select.addEventListener("change", onPresetChange);
  document.getElementById("includeAcr").addEventListener("change", updatePreview);
  document.getElementById("acr").addEventListener("input", updatePreview);
  document.getElementById("includeAmr").addEventListener("change", updatePreview);
  document.getElementById("amrValues").addEventListener("input", updatePreview);
  loadConfig();
}

function loadConfig() {
  fetch("/admin/config").then(r => r.json()).then(data => {
    applyToForm(data.config);
  });
}

function applyToForm(config) {
  document.getElementById("preset").value = config.activePreset;
  document.getElementById("includeAcr").checked = config.includeAcr;
  document.getElementById("acr").value = config.authnContextClassRef;
  document.getElementById("includeAmr").checked = config.includeAmr;
  document.getElementById("amrValues").value = config.amrValues.join("\\n");
  updatePresetDesc();
  updatePreview();
}

function onPresetChange() {
  const id = document.getElementById("preset").value;
  const preset = presets.find(p => p.id === id);
  if (preset && id !== "custom") {
    document.getElementById("includeAcr").checked = preset.config.includeAcr;
    document.getElementById("acr").value = preset.config.authnContextClassRef;
    document.getElementById("includeAmr").checked = preset.config.includeAmr;
    document.getElementById("amrValues").value = preset.config.amrValues.join("\\n");
  }
  updatePresetDesc();
  updatePreview();
}

function updatePresetDesc() {
  const id = document.getElementById("preset").value;
  const preset = presets.find(p => p.id === id);
  const el = document.getElementById("preset-desc");
  if (preset) {
    el.textContent = preset.description;
  }
}

function updatePreview() {
  const includeAcr = document.getElementById("includeAcr").checked;
  const acr = document.getElementById("acr").value || "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
  const includeAmr = document.getElementById("includeAmr").checked;
  const amrValues = document.getElementById("amrValues").value.split("\\n").filter(v => v.trim());

  let xml = '<saml2:AuthnStatement AuthnInstant="...">\\n';
  if (includeAcr) {
    xml += '  <saml2:AuthnContext>\\n';
    xml += '    <saml2:AuthnContextClassRef>' + escapeHtml(acr) + '</saml2:AuthnContextClassRef>\\n';
    xml += '  </saml2:AuthnContext>\\n';
  }
  xml += '</saml2:AuthnStatement>';

  if (includeAmr && amrValues.length > 0) {
    xml += '\\n<saml2:AttributeStatement>\\n';
    xml += '  <saml2:Attribute\\n';
    xml += '      Name="http://schemas.microsoft.com/claims/authnmethodsreferences"\\n';
    xml += '      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">\\n';
    amrValues.forEach(v => {
      xml += '    <saml2:AttributeValue>' + escapeHtml(v.trim()) + '</saml2:AttributeValue>\\n';
    });
    xml += '  </saml2:Attribute>\\n';
    xml += '</saml2:AttributeStatement>';
  }

  document.getElementById("preview").textContent = xml;
}

function escapeHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function saveConfig() {
  const activePreset = document.getElementById("preset").value;
  const includeAcr = document.getElementById("includeAcr").checked;
  const includeAmr = document.getElementById("includeAmr").checked;
  const amrValues = document.getElementById("amrValues").value.split("\\n").filter(v => v.trim()).map(v => v.trim());
  const authnContextClassRef = document.getElementById("acr").value;

  const body = { includeAcr, includeAmr, amrValues, authnContextClassRef, activePreset };

  fetch("/admin/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(r => r.json()).then(data => {
    if (data.error) {
      showStatus(data.error, "error");
    } else {
      showStatus("Configuration saved successfully", "success");
      applyToForm(data.config);
    }
  }).catch(err => {
    showStatus("Failed to save: " + err.message, "error");
  });
}

function initiateLogin() {
  const fedId = document.getElementById("federationId").value.trim();
  if (!fedId || fedId.indexOf("@") < 0) {
    showStatus("Enter a valid federation ID (must contain @)", "error");
    return;
  }
  window.open("/" + encodeURIComponent(fedId), "_blank");
}

function generateOnly() {
  const fedId = document.getElementById("federationId").value.trim();
  if (!fedId || fedId.indexOf("@") < 0) {
    showStatus("Enter a valid federation ID (must contain @)", "error");
    return;
  }
  fetch("/admin/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ federationId: fedId }),
  }).then(r => r.json()).then(data => {
    if (data.error) {
      showStatus(data.error, "error");
    } else {
      showStatus("Assertion generated - use Copy buttons above", "success", "debug-status");
    }
  }).catch(err => {
    showStatus("Failed to generate: " + err.message, "error");
  });
}

function copyDebugContent(url) {
  fetch(url).then(r => r.text()).then(text => {
    navigator.clipboard.writeText(text).then(() => {
      showStatus("Copied to clipboard", "success", "debug-status");
    }).catch(() => {
      showStatus("Failed to copy", "error", "debug-status");
    });
  }).catch(() => {
    showStatus("No content available yet", "error", "debug-status");
  });
}

function showStatus(msg, type, targetId) {
  const el = document.getElementById(targetId || "status");
  el.textContent = msg;
  el.className = "status " + type;
  setTimeout(() => { el.className = "status"; }, 3000);
}

init();
</script>
</body>
</html>`);
});

/**
 * Endpoint to start Identity Provider initiated SSO. The endpoint should
 * be called with the federation ID set up in Salesforce as the part i.e.
 * GET /tom.brady@example.com
 */
app.get("/favicon.ico", (_req, res) => res.sendStatus(204));

app.get("/:federationId", (req, res) => {
    // ensure we got a federation ID
    console.log("------");
    console.log(`FederationId: ${req.params.federationId}`);
    if (req.params.federationId.indexOf("@") < 0) return res.sendStatus(404);

    // create options from base options
    const amrConfig = getConfig();
    const options: AssertionInput = {
        federationId: req.params.federationId,
        assertionConsumerServiceUrl: process.env.SAML_LOGIN_URL,
        key: Buffer.from(process.env.SAML_PRIVATE_KEY, "base64"),
        cert: cleanupPEMCertificate(Buffer.from(process.env.SAML_CERTIFICATE, "base64").toString()),
        issuer: process.env.SAML_ISSUER,
        entityId: process.env.SAML_ENTITY_ID,
        includeAcr: amrConfig.includeAcr,
        authnContextClassRef: amrConfig.authnContextClassRef,
        amrValues: amrConfig.includeAmr ? amrConfig.amrValues : undefined,
    };

    // get assertion info incl. a signed SAML assertion
    const responseOutput = buildAssertionInfo(options);

    // save debug
    lastResponseXml = responseOutput.signedResponse;

    // set response type and send form back to browser that the browser
    // can then post to the login url at the service provider
    res.type("html");
    const htmlbody = `<html>
    <body>
    <form action="${options.assertionConsumerServiceUrl}" method="post">
    <input type="hidden" name="SAMLResponse" value="${responseOutput.base64EncodedResponse}">
    </form>
    <script>
      document.forms[0].submit();
    </script>
    </body>
    </html>`;
    res.status(200).send(htmlbody);
});

/**
 * Support Service Provider (SP) initiated SSO with the HTTP-POST binding.
 *
 */
app.post("/SAML-Login", async (req, res) => {
    // get body attrs
    const _relayState = req.body.RelayState;
    const samlRequestB64 = req.body.SAMLRequest;
    const federationId = req.body.FederationId;

    // decode request
    const samlRequestXml = Buffer.from(samlRequestB64, "base64").toString();
    const samlRequestJson = await parseStringPromise(samlRequestXml);

    // save debug
    lastAuthnRequestXml = samlRequestXml;
    lastAuthnRequestJson = samlRequestJson;

    // extract x509 cert from request and add certificate PEM header/footer
    const x509cert =
        samlRequestJson["saml2p:AuthnRequest"]["ds:Signature"][0]["ds:KeyInfo"][0]["ds:X509Data"][0][
            "ds:X509Certificate"
        ][0];
    const requestCert = Buffer.from(`-----BEGIN CERTIFICATE-----\n${x509cert}\n-----END CERTIFICATE-----`);
    
    // verify the request
    try {
        verifyAuthnRequest(samlRequestXml, requestCert);
    } catch (err) {
        console.log("Unable to verify signature on request XML", err);
        return res.status(417).send("Unable to verify signature on request xml");
    }
    
    if (!federationId || !federationId.length) {
        // no federation id supplied - show username dialog
        res.type("html");
        const htmlbody = `<html>
        <body>
        <form action="/SAML-Login" method="post">
        <input type="hidden" name="SAMLRequest" value="${samlRequestB64}">
        <input type="text" name="FederationId" placeholder="Federation ID i.e. tom.brady@example.com" value="">
        <input type="submit">
        </form>
        </body>
        </html>`;
        res.status(200).send(htmlbody);
        return;
    }

    // get the authn attributes
    const authnAttrs: any = samlRequestJson["saml2p:AuthnRequest"]["$"];
    const authnId = authnAttrs.ID;
    const acsUrl = authnAttrs.AssertionConsumerServiceURL;
    const protocolBinding = authnAttrs.ProtocolBinding;
    if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" !== protocolBinding) {
        return res.status(417).send("Invalid protocol binding");
    }

    // create options
    const amrConfig = getConfig();
    const options: AssertionInput = {
        federationId: federationId,
        assertionConsumerServiceUrl: acsUrl,
        key: Buffer.from(process.env.SAML_PRIVATE_KEY, "base64"),
        cert: cleanupPEMCertificate(Buffer.from(process.env.SAML_CERTIFICATE, "base64").toString()),
        issuer: process.env.SAML_ISSUER,
        entityId: process.env.SAML_ENTITY_ID,
        signatureSHA256: true,
        digestSHA256: true,
        inResponseTo: authnId,
        includeAcr: amrConfig.includeAcr,
        authnContextClassRef: amrConfig.authnContextClassRef,
        amrValues: amrConfig.includeAmr ? amrConfig.amrValues : undefined,
    };

    // get assertion info incl. a signed SAML assertion
    const responseOutput = buildAssertionInfo(options);

    // save debug
    lastResponseXml = responseOutput.signedResponse;

    // set response type and send form back to browser that the browser
    // can then post to the login url at the service provider
    res.type("html");
    const htmlbody = `<html>
    <body>
    <form action="${options.assertionConsumerServiceUrl}" method="post">
    <input type="hidden" name="SAMLResponse" value="${responseOutput.base64EncodedResponse}">
    </form>
    <script>
      document.forms[0].submit();
    </script>
    </body>
    </html>`;
    res.status(200).send(htmlbody);
});

// listen up!
app.listen(process.env.PORT || 3000);

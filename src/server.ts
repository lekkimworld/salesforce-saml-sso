import {parseStringPromise} from "xml2js";
import express from "express";
import { AssertionInput, buildAssertionInfo, cleanupPEMCertificate, verifyAuthnRequest } from "./saml-utils";
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
        }
    }
}

const app = express();
app.use(express.urlencoded({ extended: true }));

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

/**
 * Endpoint to start Identity Provider initiated SSO. The endpoint should
 * be called with the federation ID set up in Salesforce as the part i.e.
 * GET /tom.brady@example.com
 */
app.get("/:federationId", (req, res) => {
    // ensure we got a federation ID
    console.log("------");
    console.log(`FederationId: ${req.params.federationId}`);
    if (req.params.federationId.indexOf("@") < 0) return res.send(404);

    // create options from base options
    const options: AssertionInput = {
        federationId: req.params.federationId,
        assertionConsumerServiceUrl: process.env.SAML_LOGIN_URL,
        key: Buffer.from(process.env.SAML_PRIVATE_KEY, "base64"),
        cert: cleanupPEMCertificate(Buffer.from(process.env.SAML_CERTIFICATE, "base64").toString()),
        issuer: process.env.SAML_ISSUER,
        entityId: process.env.SAML_ENTITY_ID
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

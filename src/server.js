const express = require("express");
const { buildAssertionInfo, cleanupPEMCertificate } = require("./saml-utils.js");
require("dotenv").config();

const app = express();
app.get("/:federationId", (req, res) => {
    // ensure we got a federation ID
    console.log("------");
    console.log(`FederationId: ${req.params.federationId}`);
    if (req.params.federationId.indexOf("@") < 0) return res.send(404);

    // create options
    const options = {
        key: Buffer.from(process.env.SAML_PRIVATE_KEY, "base64").toString(),
        cert: cleanupPEMCertificate(Buffer.from(process.env.SAML_CERTIFICATE, "base64").toString()),
        issuer: process.env.SAML_ISSUER,
        federationId: req.params.federationId,
        orgId: process.env.SAML_ORGID,
        entityId: process.env.SAML_ENTITY_ID,
        loginUrl: process.env.SAML_LOGIN_URL,
    };

    // get assertion info incl. a signed SAML assertion
    const assertionInfo = buildAssertionInfo(options);
    console.log(JSON.stringify(assertionInfo, undefined, 2));

    // set response type and send form back to browser that the browser
    // can then post to the login url at the service provider
    res.type("html");
    const htmlbody = `<html>
    <body>
    <form action="${assertionInfo.loginUrl}" method="post">
    <input type="hidden" name="SAMLResponse" value="${assertionInfo.base64EncodedSignedAssertion}">
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

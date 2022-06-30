const SignedXml = require("xml-crypto").SignedXml;
const uuid = require("uuid").v4;
const moment = require("moment-timezone");

const DATETIME_FORMAT = "YYYY-MM-DDTHH:mm:ss.SSS[Z]";
const CERT_BEGIN = "-----BEGIN CERTIFICATE-----";
const CERT_END = "-----END CERTIFICATE-----";

/**
 * Removes the BEGIN CERTIFICATE and END CERTIFICATE lines from a PEM encoded 
 * certificate and strips newlines.
 * 
 */
const cleanupPEMCertificate = (cert) => {
  let work;
  const idxStart = cert.indexOf(CERT_BEGIN);
  if (idxStart !== -1) {
    // cut
    const idxEnd = cert.indexOf("-----END CERTIFICATE-----", idxStart);
    work = cert.substring(idxStart + CERT_BEGIN.length, idxEnd);
  } else {
    work = cert;
  }
  work = work.replace(/\n/g, "");
  return work;
}

/**
 * Builds up a SAML assertion using the options provided based on the provided options which are:
 * - issuer (the Identity Provider)
 * - federationId (the federation ID of the subject)
 * - loginUrl (the login URL of the Service Provider)
 * - entityId (the entity ID of the Service Provider)
 * - orgId (org ID of the Service Provider to build the login URL)
 * - validityMins (optional the validity time in minutes, defaults to 5 minutes)
 * 
 * Returns a data structure with the following data:
 * - assertion (the SAML XML assertion)
 * - signedAssertion (the signed assertion)
 * - base64EncodedSignedAssertion (base64 encoded version of the signed assertion)
 * - loginUrl (the URL the assertion should be posted to at the Service Provider)
 * 
 * @param {*} options 
 * @returns 
 */
const buildAssertionInfo = (options) => {
    // prep assertion
    const str_now_dt = moment.utc().format(DATETIME_FORMAT);
    const str_end_dt = moment.utc().add(options.validityMins ? Number.parseInt(options.validityMins) : 5, "minutes").format(DATETIME_FORMAT);
    let assertion = `<?xml version="1.0" encoding="UTF-8"?>
    <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" Destination="${
        options.loginUrl
    }" ID="${uuid()}" IssueInstant="${str_now_dt}" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">${
        options.issuer
    }</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="${uuid()}" IssueInstant="${str_now_dt}" Version="2.0"><saml2:Issuer>${
        options.issuer
    }</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${
        options.federationId
    }</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="${str_end_dt}" Recipient="${
        options.loginUrl
    }"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="${str_now_dt}" NotOnOrAfter="${str_end_dt}"><saml2:AudienceRestriction><saml2:Audience>${
        options.entityId
    }</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="${str_now_dt}"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement>`;
    assertion += `</saml2:Assertion></saml2p:Response>`;

    // sign
    function MyKeyInfo() {
        this.getKeyInfo = function (key, prefix) {
            prefix = prefix || "";
            prefix = prefix ? prefix + ":" : prefix;
            return (
                "<" +
                prefix +
                "X509Data><" +
                prefix +
                "X509Certificate>" +
                options.cert +
                "</" +
                prefix +
                "X509Certificate></" +
                prefix +
                "X509Data>"
            );
        };
        this.getKey = function (keyInfo) {
            return options.cert;
        };
    }
    const sign = new SignedXml();
    sign.addReference("//*[local-name(.)='Response']", [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
    ]);
    sign.signingKey = options.key;
    sign.keyInfoProvider = new MyKeyInfo();
    sign.computeSignature(assertion);
    const signedAssertion = sign.getSignedXml();

    // build result
    const result = {};
    result.assertion = assertion;
    result.signedAssertion = signedAssertion;
    result.base64EncodedSignedAssertion = Buffer.from(signedAssertion).toString("base64");
    result.loginUrl = options.loginUrl;

    // return
    return result;
}

module.exports = {
    buildAssertionInfo,
    cleanupPEMCertificate
};


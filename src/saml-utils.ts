import {SignedXml, xpath } from "xml-crypto";
import {v4 as uuid} from "uuid";
import moment from "moment-timezone";
import { DOMParser } from "@xmldom/xmldom";

const DATETIME_FORMAT = "YYYY-MM-DDTHH:mm:ss.SSS[Z]";
const CERT_BEGIN = "-----BEGIN CERTIFICATE-----";
const CERT_END = "-----END CERTIFICATE-----";

/**
 * Removes the BEGIN CERTIFICATE and END CERTIFICATE lines from a PEM encoded 
 * certificate and strips newlines.
 * 
 */
export const cleanupPEMCertificate = (cert: string) : Buffer => {
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
  return Buffer.from(work);
}

const getTimestamps = (options: AssertionInput) : SamlTimestamps => {
    // prep assertion
    const str_now_dt = moment.utc().format(DATETIME_FORMAT);
    const str_end_dt = moment
        .utc()
        .add(options.validityMinutes || 5, "minutes")
        .format(DATETIME_FORMAT);
    return {
        now: str_now_dt,
        end: str_end_dt
    }
}

export const signXml = (options: AssertionInput, xml: string, nodename: string) : string => {
    // prep signing
    let sign = new SignedXml();
    sign.addReference(
        `//*[local-name(.)='${nodename}']`,
        ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
        options.digestSHA256 ? "http://www.w3.org/2001/04/xmlenc#sha256" : "http://www.w3.org/2000/09/xmldsig#sha1"
    );
    sign.signatureAlgorithm = options.signatureSHA256
        ? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        : "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sign.signingKey = options.key;
    sign.keyInfoProvider = {
        file: "not used",
        getKeyInfo: function (key, prefix) {
            prefix = prefix || "";
            prefix = prefix ? prefix + ":" : prefix;
            const result =
                "<" +
                prefix +
                "X509Data><" +
                prefix +
                "X509Certificate>" +
                options.cert.toString().replace(/[\n\r]/g, "") +
                "</" +
                prefix +
                "X509Certificate></" +
                prefix +
                "X509Data>";
            return result;
        },
        getKey: function (keyInfo) {
            return options.cert;
        },
    };
    sign.computeSignature(xml);

    // sign
    let signedXml = sign.getSignedXml();

    // return
    return signedXml;
}

export const buildAssertion = (options: AssertionInput): BuildAssertionOutput => {
    // get timestamps
    const timestamps = getTimestamps(options);

    // build assertion
    let assertion = `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="${uuid()}" IssueInstant="${
        timestamps.now
    }" Version="2.0"><saml2:Issuer>${
        options.issuer
    }</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${
        options.federationId
    }</saml2:NameID><saml2:SubjectConfirmation `;
    if (options.inResponseTo) assertion += `InResponseTo="${options.inResponseTo}" `;
    assertion += `Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="${
        timestamps.end
    }" Recipient="${
        options.assertionConsumerServiceUrl
    }"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="${timestamps.now}" NotOnOrAfter="${
        timestamps.end
    }"><saml2:AudienceRestriction><saml2:Audience>${
        options.entityId
    }</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="${
        timestamps.now
    }"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>`;

    // sign
    const signedAssertion = signXml(options, assertion, "Assertion");

    // return
    return {
        assertion, signedAssertion
    };
};

const buildResponse = (options: AssertionInput, signedAssertion: string) : BuildResponseOutput => {
    // get timestamps
    const timestamps = getTimestamps(options);

    // build response
    let response = `<?xml version="1.0" encoding="UTF-8"?>
    <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" Destination="${
        options.assertionConsumerServiceUrl
    }" ID="${uuid()}" IssueInstant="${timestamps.now}" Version="2.0"`;
    if (options.inResponseTo) response += ` InResponseTo="${options.inResponseTo}"`
    response += `><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">${
        options.issuer
    }</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>${signedAssertion}</saml2p:Response>`;

    // sign response
    const signedResponse = signXml(options, response, "Response");

    // return
    return {
        response, signedResponse, 
        base64EncodedResponse: Buffer.from(signedResponse).toString("base64")
    };
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
export const buildAssertionInfo = (options: AssertionInput): BuildResponseOutput => {
    // get assertion
    const assertionOutput = buildAssertion(options);

    // build response with signed assertion
    const responseOutput = buildResponse(options, assertionOutput.signedAssertion);

    // return
    return responseOutput;
};

export const verifyAuthnRequest = (xml: string, cert: Buffer) => {
    const doc = new DOMParser().parseFromString(xml);
    const signature = xpath(
        doc,
        "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']"
    )[0];

    var sig = new SignedXml();
    sig.keyInfoProvider = {
        file: "not used",
        //@ts-ignore
        getKeyInfo(_key, _prefix) {
            return undefined;
        },
        getKey: function (keyInfo) {
            return cert;
        },
    };
    sig.loadSignature(signature as Node);
    sig.checkSignature(xml);
}

export type BuildAssertionOutput = {
    assertion: string;
    signedAssertion: string;
};

export type BuildResponseOutput = {
    response: string;
    signedResponse: string;
    base64EncodedResponse: string;
};

export type AssertionInput = {
    signatureSHA256?: boolean; // should we use rsa-256 for the signature
    digestSHA256?: boolean; // should we use sha256 for the digest
    validityMinutes?: number; // validity time in minutes - defaults to 5 minutes
    assertionConsumerServiceUrl: string; // where are we sending the assertion ("login url")
    issuer: string; // who issued the assertion - the IdP
    entityId: string; // who's the recipient of the assertion - the SP
    federationId: string; // who has been authenticated
    key: Buffer; // key used to sign the assertion
    cert: Buffer; // the certificate matching the key
    inResponseTo?: string;  // if response is to an AuthnRequest add the InReponseTo attribute
};

type SamlTimestamps = {
    now: string;
    end: string;
}
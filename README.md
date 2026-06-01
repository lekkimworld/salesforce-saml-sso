# Salesforce SAML SSO PoC #
This repo shows how to do SAML Identity Provider Initiated SSO with Salesforce as the Service Provider. It also has a very simple implementation of the HTTP-Post binding to show how to do Service Provider (SP) initiated SSO with Salesforce. The application is written in TypeScript/Node.js and can be run locally when using the IdP initiated SSO or on a TLS capable hosting provider (such as Heroku) when doing SP initiated SSO as Salesforce require the IdP Login URL to use HTTPS.

The application includes an admin interface for configuring AMR (Authentication Methods Reference) and ACR (Authentication Context Class Reference) claims sent in the SAML assertion. This allows simulating different MFA scenarios as seen by Salesforce, including how Microsoft Entra ID sends these claims.

## Configuration ##
Configuration is read from the environment:
- `SAML_LOGIN_URL` The URL at Salesforce (Service Provider) to send the signed assertion to when using IdP initiated SSO. This value can be found on the Single Sign On Settings in Salesforce Setup. 
* `SAML_ISSUER` The `Issuer` as configured on the Single Sign On Settings in Salesforce
* `SAML_ENTITY_ID` The `Entity ID` as configured on the Single Sign On Settings in Salesforce
* `SAML_PRIVATE_KEY` Base64 encoded private key in PEM format to sign the SAML assertion sent to Salesforce
* `SAML_CERTIFICATE` Base64 encoded certificate of the IdP to include in the SAML response

## Usage ##
Install dependencies and run the app locally (listens on port 3000)
```
npm install
npm run server
```

## Admin Interface ##
Visit `http://localhost:3000/admin` to configure AMR/ACR claims. The admin page lets you:
- Select from presets simulating Microsoft Entra ID authentication scenarios
- Configure custom AMR values and AuthnContextClassRef URIs
- Preview the XML that will be included in the next assertion

Configuration persists in memory between requests (resets on server restart). All subsequent SSO assertions will include the configured claims until changed.

### Salesforce MFA Tiers ###
Salesforce categorizes AMR claim values into three tiers for MFA enforcement:

**Phishing-Resistant MFA:** cert, fido, fido2, fpt, hwk, iris, pin, pki, pop, retina, sc, Smartcard, swk, TLSClient, user, vbm, wia, X509

**Standard MFA:** Face, mobiletwofactorcontract, multipleauthn, okta_verify, passkey, webauthn

**Weak / No MFA:** pwd, sms, tel, email

The admin presets are organized around these tiers so you can quickly test how Salesforce responds to each level.

## Identity Provider (IdP) Initiated SSO ##
Call the application with the Federation ID as a parameter to perform SSO towards the Salesforce Service Provider. The application will mint and sign a SAML assertion and send the SAML response to the Service Provider (SP, Salesforce). The provided Federation ID should be set as the federation identity on a user in Salesforce.

### Example ###
To perform IdP initiated SSO for `tom.brady@example.com` as the federation ID open the following URL in a browser.
```
http://localhost:3000/tom.brady@example.com
```

## Service Provider (SP) Initiated SSO ##
Configure Salesforce Single Sign-on Settings with the app endpoint for the Identity Provider login url (`https://foo-app.herokuapp.com/SAML-Login`) and add the single sign-on setting to the My Domain login configuration in Salesforce. Now open the login page of the org and click the single sign-on setting name to be redirected to the application with an AuthnRequest signed by Salesforce. The app will use the certificate in the AuthnRequest to verify the signature and present a web page allowing the input of a federation ID (e.g. `tom.brady@example.com`). Once submitted the app will mint and sign an assertion and POST it back to the Assertion Consumption Service (ACS) URL specified in the AuthnRequest.

## Debug Endpoints ##
- `GET /debug/last/authn/xml` — Last received AuthnRequest (XML)
- `GET /debug/last/authn/json` — Last received AuthnRequest (JSON)
- `GET /debug/last/response/xml` — Last sent SAML response (XML)

## Generate certificates ##
OpenSSL commands to generate a private key without a password and a certificate in PEM format. Specify the key length to use i.e. `2048`, `3072` or `4096`.
```
openssl genrsa -des3 -out rootca.key 4096
openssl rsa -in rootca.key -out rootca_no_password.key
openssl req -x509 -new -nodes -key rootca_no_password.key -sha256 -days 1024 -out rootca.crt
openssl x509 -in rootca.crt -pubkey > rootca_publickey.pem

// put into environment file (assumed to exist)
echo "SAML_PRIVATE_KEY=$(cat rootca_no_password.key | base64 -i -)" >> .env
echo "SAML_CERTIFICATE=$(cat rootca.crt | base64 -i -)" >> .env
```

## Keystore ##
To generate a Java keystore to import in Salesforce please refer to the following link. 
https://lekkimworld.com/2019/12/09/generate-a-java-keystore-jks-which-is-importable-in-salesforce/

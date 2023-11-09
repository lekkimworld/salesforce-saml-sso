# Salesforce Identity Provider Initiated SAML SSO #
Repo to show how to do SAML Identity Provider Initiated SSO with SAML using Salesforce as the Service Provider. The SAML assertion is issued and signed by a simple Web App potentially running on Heroku or locally. The 

## Configuration ##
Configuration is read from the environment:
- `SAML_LOGIN_URL` The login URL at Salesforce (Service Provider). Configured in Single Sign On Settings in Setup. 
* `SAML_ISSUER` The `Issuer` as configured on the Single Sign On Settings in Salesforce
* `SAML_ENTITY_ID` The `Entity ID` as configured on the Single Sign On Settings in Salesforce
* `SAML_PRIVATE_KEY` Base64 encoded private key in PEM format to sign the SAML assertion
* `SAML_CERTIFICATE` Base64 encoded certificate of the IdP 

## Usage ##
Install dependencies and run the app locally (listens of port 3000)
```
npm install
npm run server
```

Then call the service with the Federation ID as a part parameter to perform SSO towards the Salesforce Service Provider. We require that Federation ID is set as the identity used and a Federation ID is set on the User records in Salesforce. 

### Example ###
```
http://localhost:3000/tom.brady@example.com
```

## Generate certificates ##
OpenSSL commands to generate a private key without a password and a certificate in PEM format. Specify the key length to use i.e. `2048`, `3072` or `4096`.
```
openssl genrsa -des3 -out rootca.key 4096
openssl rsa -in rootca.key -out rootca_no_password.key
openssl req -x509 -new -nodes -key rootca_no_password.key -sha256 -days 1024 -out rootca.crt
openssl x509 -in rootca.crt -pubkey > rootca_publickey.pem
```

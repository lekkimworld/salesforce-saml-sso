export type AmrAcrConfig = {
  includeAcr: boolean;
  includeAmr: boolean;
  amrValues: string[];
  authnContextClassRef: string;
  activePreset: string;
};

export type AmrAcrPreset = {
  id: string;
  name: string;
  description: string;
  config: Omit<AmrAcrConfig, "activePreset">;
};

const presets: AmrAcrPreset[] = [
  // --- Weak / No MFA ---
  {
    id: "default",
    name: "Default (no AMR)",
    description: "No AMR attribute sent. Salesforce tier: Weak/No MFA.",
    config: {
      includeAcr: true,
      includeAmr: false,
      amrValues: [],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
    },
  },
  {
    id: "entra-pwd-only",
    name: "Entra ID - Password Only",
    description: "Single-factor password. Salesforce tier: Weak/No MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["pwd"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
    },
  },
  // --- Standard MFA ---
  {
    id: "entra-pwd-webauthn",
    name: "Entra ID - Password + WebAuthn",
    description: "Password with WebAuthn (passkey/platform authenticator). Salesforce tier: Standard MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["webauthn", "pwd"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    },
  },
  {
    id: "entra-pwd-face",
    name: "Entra ID - Password + Face",
    description: "Password with facial recognition (Windows Hello). Salesforce tier: Standard MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["Face", "pwd"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    },
  },
  {
    id: "entra-pwd-passkey",
    name: "Entra ID - Passkey",
    description: "Passkey authentication. Salesforce tier: Standard MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["passkey"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    },
  },
  {
    id: "entra-pwd-multipleauthn",
    name: "Entra ID - Multiple Authentication",
    description: "Generic multiple-authentication claim. Salesforce tier: Standard MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["multipleauthn", "pwd"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    },
  },
  // --- Phishing-Resistant MFA ---
  {
    id: "entra-pwd-fido2",
    name: "Entra ID - Password + FIDO2",
    description: "Password with FIDO2 security key. Salesforce tier: Phishing-Resistant MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["fido2", "pwd"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    },
  },
  {
    id: "entra-pwd-hwk",
    name: "Entra ID - Password + Hardware Key",
    description: "Password with hardware-secured key proof. Salesforce tier: Phishing-Resistant MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["hwk", "pwd"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    },
  },
  {
    id: "entra-wia",
    name: "Entra ID - Windows Integrated Auth",
    description: "Windows Integrated Authentication (Kerberos). Salesforce tier: Phishing-Resistant MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["wia"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    },
  },
  {
    id: "entra-x509",
    name: "Entra ID - X.509 Certificate",
    description: "Certificate-based authentication. Salesforce tier: Phishing-Resistant MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["X509"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
    },
  },
  {
    id: "entra-smartcard",
    name: "Entra ID - Smart Card",
    description: "Smart card authentication. Salesforce tier: Phishing-Resistant MFA.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: ["Smartcard"],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
    },
  },
  // --- Custom ---
  {
    id: "custom",
    name: "Custom",
    description: "Fully configurable AMR values and AuthnContextClassRef.",
    config: {
      includeAcr: true,
      includeAmr: true,
      amrValues: [],
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
    },
  },
];

let currentConfig: AmrAcrConfig = {
  includeAcr: true,
  includeAmr: false,
  amrValues: [],
  authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
  activePreset: "default",
};

export const getConfig = (): AmrAcrConfig => ({ ...currentConfig, amrValues: [...currentConfig.amrValues] });

export const setConfig = (config: AmrAcrConfig): void => {
  currentConfig = { ...config, amrValues: [...config.amrValues] };
};

export const applyPreset = (presetId: string): AmrAcrConfig => {
  const preset = presets.find((p) => p.id === presetId);
  if (!preset) throw new Error(`Unknown preset: ${presetId}`);
  currentConfig = { ...preset.config, amrValues: [...preset.config.amrValues], activePreset: presetId };
  return getConfig();
};

export const getPresets = (): AmrAcrPreset[] => presets;

// Which copy of the app this code is running in — a browser tab, or the app the user
// installed to their dock/home screen.
//
// This matters because the two are ONE origin but not one device. An installed app
// shares the installing browser's storage while being a separate application to the
// OS, which reaches a different platform authenticator: on macOS Chrome a browser tab
// is answered by iCloud Keychain (which implements the WebAuthn PRF extension the
// keystore is derived from) while the installed app gets Chrome's own profile-bound
// store, which reports prf.enabled: false. Same account record, one context able to
// open it and the other not.
//
// Rather than let the two fight over one record, they are kept apart: each context
// gets its own database and its own device-local preferences, and behaves as its own
// device — set up once, holding its own keys, unlocking with whatever it can actually
// reach. Nothing here decides what is REQUESTED of an authenticator; it only decides
// where this context's own state lives.

const INSTALLED_DISPLAY_MODES = ['standalone', 'minimal-ui', 'fullscreen', 'window-controls-overlay'];

// isIOSWebApp marks an iOS/iPadOS home-screen web app. The OS gives those their own
// storage container already, so they are separate from Safari without our help.
function isIOSWebApp(): boolean {
  try {
    return (navigator as unknown as { standalone?: boolean }).standalone === true;
  } catch {
    return false;
  }
}

// isInstalledApp reports whether this is an installed app rather than a browser tab.
export function isInstalledApp(): boolean {
  try {
    if (isIOSWebApp()) return true;
    return INSTALLED_DISPLAY_MODES.some(mode => window.matchMedia(`(display-mode: ${mode})`).matches);
  } catch {
    return false;
  }
}

// usesOwnStore reports whether this context keeps its state under its own names.
//
// Only where the platform hasn't already separated us: an iOS web app has its own
// storage container from the OS, so renaming its database would orphan a working
// install and force a pointless re-pair on a platform where passkeys work fine.
export function usesOwnStore(): boolean {
  return isInstalledApp() && !isIOSWebApp();
}

// storageKey namespaces a device-local web-storage key to this context. Account-level
// preferences do NOT belong here — those live in the personal KV (see
// api/settingsStore.ts) precisely so they follow the user to every device.
//
// Legacy keys written by older builds under their bare name are the one exception:
// prefixing those would mean never finding them again (see hooks/useContacts.ts).
export function storageKey(name: string): string {
  return usesOwnStore() ? `app:${name}` : name;
}

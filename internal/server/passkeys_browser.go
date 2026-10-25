package server

import (
	"fmt"
	"net/http"
)

const passkeyRegistrationTemplate = `<section class="passkey-panel" id="passkey-registration" data-csrf="{{.CSRF}}"><div class="self-section-head"><div><h2>My Passkeys</h2><p>Only public, non-identifying device metadata is shown.</p></div><span class="count">{{len .Passkeys}}</span></div>{{range .Passkeys}}<article class="passkey-row"><span><strong>{{.Name}}</strong><small>Added {{.Created}} · last used {{.LastUsed}}</small><span class="badge neutral">{{.Kind}}</span></span><form class="passkey-revoke-form" data-management-id="{{.ManagementID}}"><label><span>Current AD password</span><input type="password" name="password" autocomplete="current-password" required></label><button class="danger small" type="submit">Remove</button></form><p class="passkey-status" role="status" aria-live="polite"></p></article>{{else}}<p class="self-empty">No Passkeys are registered for your account.</p>{{end}}<div class="passkey-add"><div class="self-section-head"><div><h2>Add a Passkey</h2><p>Confirm your current AD password, then use this device or a security key.</p></div></div><form class="login-form" id="passkey-registration-form"><label><span>Passkey name</span><input name="name" maxlength="64" autocomplete="off" placeholder="e.g. Laptop or security key" required></label><label><span>Current AD password</span><input type="password" name="password" autocomplete="current-password" placeholder="Confirm your identity" required></label><button type="submit">Register Passkey</button></form><p class="passkey-status" id="passkey-registration-status" role="status" aria-live="polite"></p></div></section>`

const passkeyLoginTemplate = `<section class="passkey-panel passkey-login"><div class="passkey-divider"><span>or</span></div><button type="button" id="passkey-login-button">Continue with a Passkey</button><p class="passkey-status" id="passkey-login-status" role="status" aria-live="polite"></p></section>`

const passkeyBrowserJS = `"use strict";
(() => {
  const encode = buffer => {
    let value = "";
    new Uint8Array(buffer).forEach(byte => { value += String.fromCharCode(byte); });
    return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const decode = value => {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
    const bytes = atob(padded);
    return Uint8Array.from(bytes, character => character.charCodeAt(0));
  };
  const request = async (path, body, csrf) => {
    const headers = {"Content-Type": "application/json", "Accept": "application/json"};
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(path, {method: "POST", headers, body: JSON.stringify(body), credentials: "same-origin"});
    if (!response.ok) throw new Error("request_failed");
    return response.json();
  };
  const creationOptions = value => {
    value.challenge = decode(value.challenge);
    value.user.id = decode(value.user.id);
    (value.excludeCredentials || []).forEach(item => { item.id = decode(item.id); });
    return value;
  };
  const requestOptions = value => {
    value.challenge = decode(value.challenge);
    (value.allowCredentials || []).forEach(item => { item.id = decode(item.id); });
    return value;
  };
  const registrationResponse = credential => ({
    id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response: {clientDataJSON: encode(credential.response.clientDataJSON), attestationObject: encode(credential.response.attestationObject), transports: credential.response.getTransports ? credential.response.getTransports() : []},
    clientExtensionResults: credential.getClientExtensionResults()
  });
  const authenticationResponse = credential => ({
    id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response: {clientDataJSON: encode(credential.response.clientDataJSON), authenticatorData: encode(credential.response.authenticatorData), signature: encode(credential.response.signature), userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : ""},
    clientExtensionResults: credential.getClientExtensionResults()
  });
  const supported = window.isSecureContext && window.PublicKeyCredential && navigator.credentials;
  const show = (element, message, error) => { element.textContent = message; element.classList.toggle("error", Boolean(error)); };
  const loginButton = document.getElementById("passkey-login-button");
  const loginStatus = document.getElementById("passkey-login-status");
  if (loginButton) {
    if (!supported) { loginButton.disabled = true; show(loginStatus, "Passkeys are not supported in this browser or connection.", true); }
    loginButton.addEventListener("click", async () => {
      loginButton.disabled = true; show(loginStatus, "Waiting for your Passkey…", false);
      try {
        const begin = await request("/self-service/passkeys/login/begin", {});
        const credential = await navigator.credentials.get({publicKey: requestOptions(begin.publicKey)});
        await request("/self-service/passkeys/login/complete", {ceremony_id: begin.ceremony_id, response: authenticationResponse(credential)});
        location.assign("/self-service");
      } catch (_) { show(loginStatus, "Passkey sign-in was cancelled or could not be completed.", true); loginButton.disabled = false; }
    });
  }
  const registration = document.getElementById("passkey-registration-form");
  const registrationPanel = document.getElementById("passkey-registration");
  const registrationStatus = document.getElementById("passkey-registration-status");
  if (registration) {
    const button = registration.querySelector("button");
    if (!supported) { button.disabled = true; show(registrationStatus, "Passkeys are not supported in this browser or connection.", true); }
    registration.addEventListener("submit", async event => {
      event.preventDefault(); button.disabled = true; show(registrationStatus, "Waiting for your Passkey…", false);
      const fields = new FormData(registration);
      try {
        const begin = await request("/self-service/passkeys/registration/begin", {password: fields.get("password")}, registrationPanel.dataset.csrf);
        registration.elements.password.value = "";
        const credential = await navigator.credentials.create({publicKey: creationOptions(begin.publicKey)});
        await request("/self-service/passkeys/registration/complete", {ceremony_id: begin.ceremony_id, name: fields.get("name"), response: registrationResponse(credential)}, registrationPanel.dataset.csrf);
        registration.reset(); show(registrationStatus, "Passkey registered successfully.", false);
      } catch (_) { registration.elements.password.value = ""; show(registrationStatus, "Registration was cancelled or could not be completed.", true); }
      finally { button.disabled = false; }
    });
  }
  document.querySelectorAll(".passkey-revoke-form").forEach(form => {
    const button = form.querySelector("button");
    const status = form.parentElement.querySelector(".passkey-status");
    form.addEventListener("submit", async event => {
      event.preventDefault(); button.disabled = true; show(status, "Removing Passkey…", false);
      try {
        await request("/self-service/passkeys/revoke", {management_id: form.dataset.managementId, password: form.elements.password.value}, registrationPanel.dataset.csrf);
        form.elements.password.value = "";
        location.reload();
      } catch (_) { form.elements.password.value = ""; show(status, "The Passkey could not be removed.", true); button.disabled = false; }
    });
  });
})();`

func passkeyBrowserScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, passkeyBrowserJS)
}

import * as jose from "jose";

async function verifySignature(request, webhookSecret) {
  const payload = await request.clone().text();
  const sigHeader = request.headers.get("x-hub-signature-256") || "";
  if (!sigHeader.startsWith("sha256=")) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(webhookSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const expected = "sha256=" + Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  return crypto.timingSafeEqual(encoder.encode(sigHeader), encoder.encode(expected));
}

async function appJWT(appId, pem) {
  const alg = "RS256";
  const now = Math.floor(Date.now() / 1000);
  const privateKey = await jose.importPKCS8(pem, alg);
  return new jose.SignJWT({})
    .setProtectedHeader({ alg })
    .setIssuedAt(now - 60)
    .setExpirationTime(now + 9 * 60)
    .setIssuer(appId)
    .sign(privateKey);
}

async function getInstallationId(appJwt, owner, repo) {
  // Lookup installation for a specific repo if INSTALLATION_ID not provided
  const url = `https://api.github.com/repos/${owner}/${repo}/installation`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: "application/vnd.github+json"
    }
  });
  if (!res.ok) throw new Error(`installation lookup failed: ${res.status}`);
  const data = await res.json();
  return data.id;
}

async function installationToken(appJwt, installationId) {
  const res = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: "application/vnd.github+json"
    }
  });
  if (!res.ok) throw new Error(`access_token failed: ${res.status}`);
  const data = await res.json();
  return data.token;
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("OK");

    const evt = request.headers.get("x-github-event");
    if (evt !== "dependabot_alert") return new Response("ignored", { status: 204 });

    const ok = await verifySignature(request, env.GH_WEBHOOK_SECRET);
    if (!ok) return new Response("bad signature", { status: 401 });

    const body = await request.json();

    if (body.action !== "dismissed") return new Response("ignored", { status: 204 });

    const repoFull = body.repository?.full_name; // "owner/repo"
    const [owner, repo] = (repoFull || "").split("/");
    const alertNumber = String(body.alert?.number || "");

    // Optional allowlist
    const allow = (env.REPO_ALLOWLIST || "").split(",").map(s => s.trim()).filter(Boolean);
    if (allow.length && !allow.includes(repoFull)) {
      return new Response("repo not allowed", { status: 403 });
    }

    try {
      const jwt = await appJWT(env.GH_APP_ID, env.GH_APP_PRIVATE_KEY);
      const installationId = env.GH_INSTALLATION_ID || await getInstallationId(jwt, owner, repo);
      const token = await installationToken(jwt, installationId);

      const dispatch = await fetch(`https://api.github.com/repos/${owner}/${repo}/dispatches`, {
        method: "POST",
        headers: {
          Authorization: `token ${token}`,
          Accept: "application/vnd.github+json"
        },
        body: JSON.stringify({
          event_type: "dependabot_alert_dismissed",
          client_payload: { alert_number: alertNumber }
        })
      });

      if (!dispatch.ok) {
        const t = await dispatch.text();
        return new Response(`dispatch failed: ${dispatch.status} ${t}`, { status: 502 });
      }
      return new Response("dispatched", { status: 202 });
    } catch (e) {
      return new Response(`error: ${e.message}`, { status: 500 });
    }
  }
};
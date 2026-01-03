function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function hmacSign(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  return crypto.subtle.sign("HMAC", key, enc.encode(message));
}

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const code = (body.code || "").trim();

  if (!code || code !== env.ACCESS_CODE) {
    return new Response(JSON.stringify({ ok: false }), {
      status: 401,
      headers: { "content-type": "application/json" }
    });
  }

  const payload = { full: true, exp: Date.now() + 30*24*60*60*1000 };
  const payloadStr = JSON.stringify(payload);
  const sig = await hmacSign(env.SECRET, payloadStr);

  const token =
    b64url(new TextEncoder().encode(payloadStr)) + "." + b64url(sig);

  return new Response(JSON.stringify({ ok: true, token }), {
    headers: { "content-type": "application/json" }
  });
}

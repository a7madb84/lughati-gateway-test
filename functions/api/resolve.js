function fromB64url(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
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
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= (a[i] ^ b[i]);
  return out === 0;
}

export async function onRequestGet({ request, env }) {
  const auth = request.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!token.includes(".")) {
    return new Response(JSON.stringify({ ok:false, locked:true }), {
      status: 403,
      headers: { "content-type": "application/json" }
    });
  }

  const [p64, s64] = token.split(".");
  const payloadBytes = fromB64url(p64);
  const payloadStr = new TextDecoder().decode(payloadBytes);

  const expectedSig = new Uint8Array(await hmacSign(env.SECRET, payloadStr));
  const providedSig = fromB64url(s64);

  if (!timingSafeEqual(expectedSig, providedSig)) {
    return new Response(JSON.stringify({ ok:false, locked:true }), {
      status: 403,
      headers: { "content-type": "application/json" }
    });
  }

  const payload = JSON.parse(payloadStr);
  if (!payload.full || Date.now() > payload.exp) {
    return new Response(JSON.stringify({ ok:false, locked:true }), {
      status: 403,
      headers: { "content-type": "application/json" }
    });
  }

  return new Response(JSON.stringify({ ok:true, url: env.FULL_URL }), {
    headers: { "content-type": "application/json" }
  });
}

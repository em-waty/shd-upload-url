import crypto from "crypto";

const region   = "ams3";
const bucket   = "700days";
const endpoint = `${bucket}.${region}.digitaloceanspaces.com`;

// --- limits & allowed types ---
const MAX_BYTES = 5 * 1024 * 1024 * 1024; // 5 GB
const ALLOWED_MIME = new Set(["video/mp4", "image/jpeg"]);
const ALLOWED_EXT  = new Set(["mp4", "jpg", "jpeg"]);

// Human-readable Paris timestamp: YYYY-MM-DD_HH-MM-SS-Europe-Paris
function parisTimestamp(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Paris",
    hour12: false,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit"
  }).formatToParts(date).reduce((acc, p) => (acc[p.type] = p.value, acc), {});
  return `${parts.year}-${parts.month}-${parts.day}_${parts.hour}-${parts.minute}-${parts.second}-Europe-Paris`;
}

function getSignedPutUrl(key, contentType, contentMD5, accessKey, secretKey) {
  const method = "PUT";
  const expires = Math.floor(Date.now() / 1000) + 300; // 5m
  const canonicalResource = `/${bucket}/${key}`;
  const stringToSign = [method, contentMD5 || "", contentType || "", String(expires), canonicalResource].join("\n");
  const signature = crypto.createHmac("sha1", secretKey).update(stringToSign).digest("base64");
  return `https://${endpoint}/${key}?AWSAccessKeyId=${accessKey}&Expires=${expires}&Signature=${encodeURIComponent(signature)}`;
}

function getSignedGetUrl(key, accessKey, secretKey) {
  const method = "GET";
  const expires = Math.floor(Date.now() / 1000) + 300; // 5m
  const canonicalResource = `/${bucket}/${key}`;
  const stringToSign = [method, "", "", String(expires), canonicalResource].join("\n");
  const signature = crypto.createHmac("sha1", secretKey).update(stringToSign).digest("base64");
  return `https://${endpoint}/${key}?AWSAccessKeyId=${accessKey}&Expires=${expires}&Signature=${encodeURIComponent(signature)}`;
}

export async function main(params) {
  const method = (params.__ow_method || "").toUpperCase();

  const corsHeaders = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Content-Type": "application/json"
  };

  if (!process.env.DO_ACCESS_KEY || !process.env.DO_SECRET_KEY) {
    return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: "Server misconfiguration" }) };
  }

  if (method === "OPTIONS") return { statusCode: 204, headers: corsHeaders, body: "" };
  if (method === "GET")     return { statusCode: 200, headers: corsHeaders, body: JSON.stringify({ message: "Upload endpoint is ready." }) };
  if (method !== "POST")    return { statusCode: 405, headers: corsHeaders, body: JSON.stringify({ error: "Method Not Allowed" }) };

  // Expect: filename, type (MIME), size (bytes), md5 (optional base64)
  const { filename, type, size, md5 } = params || {};
  if (!filename || !type) {
    return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Missing filename or type" }) };
  }

  // --- validate size (required) ---
  const sizeNum = Number(size);
  if (!Number.isFinite(sizeNum) || sizeNum < 0) {
    return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Missing or invalid 'size' (bytes) field" }) };
  }
  if (sizeNum > MAX_BYTES) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({
        error: "File too large",
        maxBytes: MAX_BYTES,
        receivedBytes: sizeNum,
        message: "Maximum allowed size is 5 GB"
      })
    };
  }

  // --- validate type & extension ---
  const ext = String(filename).split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.has(ext)) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: "Unsupported extension", allowed: [".mp4", ".jpg"], received: `.${ext || ""}` })
    };
  }
  if (!ALLOWED_MIME.has(type)) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: "Unsupported MIME type", allowed: ["video/mp4", "image/jpeg"], received: type })
    };
  }
  // ensure extension matches MIME (treat .jpg/.jpeg as image/jpeg)
  const mimeMatchesExt =
    (ext === "mp4"  && type === "video/mp4") ||
    ((ext === "jpg" || ext === "jpeg") && type === "image/jpeg");
  if (!mimeMatchesExt) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({
        error: "Filename extension does not match MIME type",
        filenameExt: `.${ext}`,
        mimeType: type,
        expected: ext === "mp4" ? "video/mp4" : "image/jpeg"
      })
    };
  }

  // --- validate optional MD5 (base64 of 16 bytes) ---
  let md5ToUse = "";
  if (md5) {
    try {
      const raw = Buffer.from(md5, "base64");
      if (raw.length !== 16) throw new Error("bad md5 length");
      md5ToUse = md5;
    } catch {
      return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "md5 must be base64-encoded MD5 (16 bytes)" }) };
    }
  }

  // --- build key: human-readable Paris time + short random + sanitized base name ---
  const ts  = parisTimestamp();
  const rnd = (crypto.randomUUID?.() || Math.random().toString(36)).slice(0, 8);
  const safeBase = String(filename).replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 100);
  const key = `uploads/${ts}-${rnd}-${safeBase}`;

  try {
    const uploadUrl   = getSignedPutUrl(key, type, md5ToUse, process.env.DO_ACCESS_KEY, process.env.DO_SECRET_KEY);
    const downloadUrl = getSignedGetUrl(key, process.env.DO_ACCESS_KEY, process.env.DO_SECRET_KEY);
    const fileUrl     = `https://${endpoint}/${key}`;

    const requiredHeaders = md5ToUse
      ? { "Content-Type": type, "Content-MD5": md5ToUse }
      : { "Content-Type": type };

    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({
        uploadUrl,
        downloadUrl,
        fileUrl,
        requiredHeaders,
        constraints: {
          maxBytes: MAX_BYTES,
          allowedMime: Array.from(ALLOWED_MIME),
          allowedExt: [".mp4", ".jpg"]
        }
      })
    };
  } catch (err) {
    return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: "Internal Server Error", details: err.message }) };
  }
}xxx

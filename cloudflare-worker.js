const ALLOWED_ORIGINS = new Set([
  "https://rickstreams.site",
  "https://www.rickstreams.site",
  "https://rickytriesstuff.github.io"
]);

function cors(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : "https://rickstreams.site";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Upload-Id, X-Upload-Key, X-Part-Number",
    "Access-Control-Expose-Headers": "ETag, Content-Range, Accept-Ranges",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function reply(data, status, origin, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors(origin), "Content-Type": "application/json; charset=utf-8", ...extra }
  });
}

async function requireOwner(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) throw new Error("Sign in with the RickStreams owner account first.");
  const response = await fetch(
    "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(env.FIREBASE_API_KEY),
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken: token })
    }
  );
  if (!response.ok) throw new Error("Your sign-in session could not be verified. Please log in again.");
  const data = await response.json();
  const user = data.users && data.users[0];
  if (!user || (user.email || "").toLowerCase() !== (env.OWNER_EMAIL || "").toLowerCase()) {
    throw new Error("Only the RickStreams owner can upload videos.");
  }
  return user;
}


function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function pemToBytes(pem) {
  const body = String(pem || "").replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  const binary = atob(body);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function serviceAccessToken(env) {
  if (!env.FIREBASE_SERVICE_ACCOUNT) throw new Error("Cloudflare secret FIREBASE_SERVICE_ACCOUNT is not configured yet.");
  const account = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(new TextEncoder().encode(JSON.stringify({alg:"RS256",typ:"JWT"})));
  const claim = base64url(new TextEncoder().encode(JSON.stringify({
    iss:account.client_email,
    scope:"https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/firebase.database",
    aud:"https://oauth2.googleapis.com/token",
    iat:now,
    exp:now+3600
  })));
  const unsigned = header+"."+claim;
  const key = await crypto.subtle.importKey("pkcs8",pemToBytes(account.private_key),{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["sign"]);
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5",key,new TextEncoder().encode(unsigned));
  const assertion = unsigned+"."+base64url(new Uint8Array(signature));
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token",{
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:new URLSearchParams({grant_type:"urn:ietf:params:oauth:grant-type:jwt-bearer",assertion})
  });
  const tokenData = await tokenResponse.json();
  if(!tokenResponse.ok || !tokenData.access_token) throw new Error("Could not obtain Firebase administrative access: "+(tokenData.error_description||tokenData.error||"unknown error"));
  return {token:tokenData.access_token,projectId:account.project_id};
}
const CREATOR_GRANDFATHER_CUTOFF = 1794061680000; // Accounts created on or before the user's approval time only.
async function migrateExistingAccounts(env) {
  const {token,projectId}=await serviceAccessToken(env);
  let pageToken="";
  let migrated=0;
  const dbUrl="https://"+projectId+"-default-rtdb.firebaseio.com/streamtv/creatorProfiles.json";
  const existingResponse=await fetch(dbUrl,{headers:{Authorization:"Bearer "+token}});
  if(!existingResponse.ok) throw new Error("Could not read creator profiles from Realtime Database.");
  const existing=await existingResponse.json()||{};
  const updates={};
  do {
    const endpoint="https://identitytoolkit.googleapis.com/v1/projects/"+encodeURIComponent(projectId)+"/accounts:batchGet?maxResults=1000"+(pageToken?"&pageToken="+encodeURIComponent(pageToken):"");
    const response=await fetch(endpoint,{headers:{Authorization:"Bearer "+token}});
    const data=await response.json();
    if(!response.ok) throw new Error("Could not list Firebase accounts: "+(data.error?.message||response.status));
    for(const user of (data.users||[])){
      const accountCreatedAt = Number(user.createdAt || user.metadata?.createdAt || 0);
      if (!accountCreatedAt || accountCreatedAt > CREATOR_GRANDFATHER_CUTOFF) continue;
      const previous=existing[user.localId]||{};
      updates[user.localId]={
        ...previous,
        role:"creator",
        subscriptionStatus:"grandfathered",
        creatorAccess:true,
        displayName:previous.displayName||user.displayName||((user.email||"").split("@")[0])||"Creator",
        createdAt:previous.createdAt||Date.now(),
        grandfatheredAt:previous.grandfatheredAt||Date.now(),
        grandfatheredReason:"account_existed_before_creator_fee"
      };
      migrated++;
    }
    pageToken=data.nextPageToken||"";
  } while(pageToken);
  if(migrated){
    const write=await fetch(dbUrl,{method:"PATCH",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify(updates)});
    if(!write.ok) throw new Error("Firebase refused to save grandfathered creator profiles.");
  }
  return {migrated};
}


async function requireUser(request, env) {
  const token=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
  if(!token) throw new Error("Please sign in first.");
  const response=await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key="+encodeURIComponent(env.FIREBASE_API_KEY),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({idToken:token})});
  if(!response.ok) throw new Error("Your sign-in session could not be verified. Please log in again.");
  const data=await response.json(), user=data.users&&data.users[0];
  if(!user) throw new Error("Account not found.");
  return user;
}
function paypalBase(env){return env.PAYPAL_MODE==="live"?"https://api-m.paypal.com":"https://api-m.sandbox.paypal.com";}
async function paypalToken(env){
  if(!env.PAYPAL_CLIENT_ID||!env.PAYPAL_CLIENT_SECRET) throw new Error("PayPal credentials are missing from Cloudflare.");
  const auth=btoa(env.PAYPAL_CLIENT_ID+":"+env.PAYPAL_CLIENT_SECRET);
  const r=await fetch(paypalBase(env)+"/v1/oauth2/token",{method:"POST",headers:{Authorization:"Basic "+auth,"Content-Type":"application/x-www-form-urlencoded"},body:"grant_type=client_credentials"});
  const d=await r.json(); if(!r.ok||!d.access_token) throw new Error("PayPal authentication failed: "+(d.error_description||d.error||r.status));
  return d.access_token;
}
async function paypalRequest(env,path,method="GET",body=null){
  const token=await paypalToken(env);
  const r=await fetch(paypalBase(env)+path,{method,headers:{Authorization:"Bearer "+token,"Content-Type":"application/json",Prefer:"return=representation"},...(body?{body:JSON.stringify(body)}:{})});
  const d=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error("PayPal API error: "+(d.message||d.details?.[0]?.description||r.status));
  return d;
}
async function setupPaypalPlan(env){
  if(!env.CREATOR_SUBSCRIPTIONS) throw new Error("Cloudflare KV binding CREATOR_SUBSCRIPTIONS is missing.");
  const product=await paypalRequest(env,"/v1/catalogs/products","POST",{name:"RickStreams Creator Membership",description:"Monthly creator membership for RickStreams",type:"SERVICE",category:"SOFTWARE"});
  const plan=await paypalRequest(env,"/v1/billing/plans","POST",{product_id:product.id,name:"RickStreams Creator Monthly",description:"RickStreams creator membership, billed monthly",billing_cycles:[{frequency:{interval_unit:"MONTH",interval_count:1},tenure_type:"REGULAR",sequence:1,total_cycles:0,pricing_scheme:{fixed_price:{value:"1.99",currency_code:"USD"}}}],payment_preferences:{auto_bill_outstanding:true,setup_fee_failure_action:"CANCEL",payment_failure_threshold:1}});
  await paypalRequest(env,"/v1/billing/plans/"+encodeURIComponent(plan.id)+"/activate","POST",{});
  await env.CREATOR_SUBSCRIPTIONS.put("paypal:plan_id",plan.id);
  return {productId:product.id,planId:plan.id};
}
async function createPaypalSubscription(request,env,user){
  if(!env.CREATOR_SUBSCRIPTIONS) throw new Error("Cloudflare KV binding CREATOR_SUBSCRIPTIONS is missing.");
  const planId=await env.CREATOR_SUBSCRIPTIONS.get("paypal:plan_id");
  if(!planId) throw new Error("The PayPal creator plan has not been configured by the site owner yet.");
  const base="https://rickstreams.site";
  const sub=await paypalRequest(env,"/v1/billing/subscriptions","POST",{plan_id:planId,custom_id:user.localId,application_context:{brand_name:"RickStreams",locale:"en-US",user_action:"SUBSCRIBE_NOW",shipping_preference:"NO_SHIPPING",return_url:base+"/?creator_payment=return",cancel_url:base+"/?creator_payment=cancel"}});
  const approve=(sub.links||[]).find(x=>x.rel==="approve")?.href;
  if(!approve) throw new Error("PayPal did not return an approval link.");
  await env.CREATOR_SUBSCRIPTIONS.put("subscription:"+sub.id,JSON.stringify({uid:user.localId,status:sub.status||"APPROVAL_PENDING",createdAt:Date.now()}));
  return {subscriptionId:sub.id,approvalUrl:approve,status:sub.status};
}
async function handlePaypalWebhook(request,env){
  if(!env.PAYPAL_WEBHOOK_ID) throw new Error("PAYPAL_WEBHOOK_ID is not configured.");
  if(!env.CREATOR_SUBSCRIPTIONS) throw new Error("Cloudflare KV binding CREATOR_SUBSCRIPTIONS is missing.");
  const event=await request.json();
  const h=request.headers;
  const verification=await paypalRequest(env,"/v1/notifications/verify-webhook-signature","POST",{
    auth_algo:h.get("paypal-auth-algo"),cert_url:h.get("paypal-cert-url"),
    transmission_id:h.get("paypal-transmission-id"),transmission_sig:h.get("paypal-transmission-sig"),
    transmission_time:h.get("paypal-transmission-time"),webhook_id:env.PAYPAL_WEBHOOK_ID,webhook_event:event
  });
  if(verification.verification_status!=="SUCCESS") throw new Error("PayPal webhook signature verification failed.");
  const resource=event.resource||{};
  const subscriptionId=resource.id||resource.billing_agreement_id||resource.subscription_id;
  let mapping=subscriptionId?await env.CREATOR_SUBSCRIPTIONS.get("subscription:"+subscriptionId,"json"):null;
  const uid=resource.custom_id||mapping?.uid;
  if(!uid) return {received:true,ignored:true};
  const activeEvents=["BILLING.SUBSCRIPTION.ACTIVATED","PAYMENT.SALE.COMPLETED"];
  const inactiveEvents=["BILLING.SUBSCRIPTION.CANCELLED","BILLING.SUBSCRIPTION.SUSPENDED","BILLING.SUBSCRIPTION.EXPIRED","BILLING.SUBSCRIPTION.PAYMENT.FAILED","PAYMENT.SALE.REVERSED","PAYMENT.SALE.REFUNDED"];
  if(activeEvents.includes(event.event_type)){
    await env.CREATOR_SUBSCRIPTIONS.put("creator:"+uid,JSON.stringify({status:"active",subscriptionId,updatedAt:Date.now(),source:event.event_type}));
    if(subscriptionId) await env.CREATOR_SUBSCRIPTIONS.put("subscription:"+subscriptionId,JSON.stringify({uid,status:"active"}));
  }else if(inactiveEvents.includes(event.event_type)){
    await env.CREATOR_SUBSCRIPTIONS.put("creator:"+uid,JSON.stringify({status:"inactive",subscriptionId,updatedAt:Date.now(),source:event.event_type}));
    if(subscriptionId) await env.CREATOR_SUBSCRIPTIONS.put("subscription:"+subscriptionId,JSON.stringify({uid,status:"inactive"}));
  }
  return {received:true};
}

function safeName(name) {
  return String(name || "upload.bin").replace(/[^a-zA-Z0-9._-]/g, "_").slice(-100);
}

function parseRange(header, size) {
  if (!header || !header.startsWith("bytes=")) return null;
  const value = header.slice(6).split(",")[0].trim();
  const match = value.match(/^(\d*)-(\d*)$/);
  if (!match || (!match[1] && !match[2])) return { invalid: true };
  let start, end;
  if (!match[1]) {
    const suffix = Number(match[2]);
    if (!suffix) return { invalid: true };
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] ? Math.min(Number(match[2]), size - 1) : size - 1;
  }
  if (start >= size || end < start) return { invalid: true };
  return { offset: start, length: end - start + 1, end };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors(origin) });
    }

    if (url.pathname.startsWith("/media/") && (request.method === "GET" || request.method === "HEAD")) {
      let key;
      try { key = decodeURIComponent(url.pathname.slice(7)); } catch { return new Response("Bad media key", { status: 400 }); }
      if (!key.startsWith("rickstreams/") || key.includes("..")) return new Response("Not found", { status: 404 });
      const metadata = await env.RICKSTREAMS_BUCKET.head(key);
      if (!metadata) return new Response("Not found", { status: 404, headers: cors(origin) });
      const headers = {
        ...cors(origin),
        "Content-Type": metadata.httpMetadata?.contentType || "application/octet-stream",
        "Accept-Ranges": "bytes",
        "Cache-Control": "public, max-age=3600",
        "ETag": metadata.httpEtag || metadata.etag,
        "Content-Length": String(metadata.size)
      };
      if (request.method === "HEAD") return new Response(null, { status: 200, headers });

      const range = parseRange(request.headers.get("Range"), metadata.size);
      if (range?.invalid) {
        headers["Content-Range"] = "bytes */" + metadata.size;
        return new Response(null, { status: 416, headers });
      }
      if (!range) {
        const object = await env.RICKSTREAMS_BUCKET.get(key);
        return new Response(object.body, { status: 200, headers });
      }
      const object = await env.RICKSTREAMS_BUCKET.get(key, { range: { offset: range.offset, length: range.length } });
      headers["Content-Length"] = String(range.length);
      headers["Content-Range"] = "bytes " + range.offset + "-" + range.end + "/" + metadata.size;
      return new Response(object.body, { status: 206, headers });
    }

    if (url.pathname === "/payments/paypal/webhook" && request.method === "POST") { try { const result=await handlePaypalWebhook(request,env); return reply(result,200,origin); } catch(error) { return reply({error:error.message||"Webhook processing failed."},400,origin); } }

    if (url.pathname === "/creator/status") { try { const user=await requireUser(request,env); const record=env.CREATOR_SUBSCRIPTIONS?await env.CREATOR_SUBSCRIPTIONS.get("creator:"+user.localId,"json"):null; return reply({status:record?.status||"inactive",creator:record||null},200,origin); } catch(error) { return reply({error:error.message},401,origin); } }

    if (!url.pathname.startsWith("/upload/") && url.pathname !== "/admin/migrate-existing-accounts" && url.pathname !== "/admin/paypal/setup-plan" && url.pathname !== "/payments/paypal/create-subscription") {
      return reply({ ok: true, service: "RickStreams upload service" }, 200, origin);
    }

    try {
      if (request.method !== "POST") return reply({ error: "Method not allowed" }, 405, origin);

      if (url.pathname === "/payments/paypal/create-subscription") {
        const user = await requireUser(request, env);
        const result = await createPaypalSubscription(request, env, user);
        return reply(result, 200, origin);
      }

      await requireOwner(request, env);

      if (url.pathname === "/admin/paypal/setup-plan") { const result=await setupPaypalPlan(env); return reply({ok:true,...result},200,origin); }

      if (url.pathname === "/admin/migrate-existing-accounts") {
        const result = await migrateExistingAccounts(env);
        return reply({ ok:true, migrated:result.migrated, status:"grandfathered" }, 200, origin);
      }

      if (url.pathname === "/upload/init") {
        const body = await request.json();
        const kind = body.kind === "thumbnail" ? "thumbnails" : "videos";
        const contentType = String(body.contentType || (kind === "videos" ? "video/mp4" : "image/jpeg"));
        if (!(kind === "videos" ? contentType.startsWith("video/") : contentType.startsWith("image/"))) {
          return reply({ error: "Unsupported file type." }, 400, origin);
        }
        const key = "rickstreams/" + kind + "/" + Date.now() + "-" + crypto.randomUUID() + "-" + safeName(body.fileName);
        const upload = await env.RICKSTREAMS_BUCKET.createMultipartUpload(key, {
          httpMetadata: { contentType }
        });
        return reply({ key, uploadId: upload.uploadId }, 200, origin);
      }

      if (url.pathname === "/upload/part") {
        const key = request.headers.get("X-Upload-Key") || "";
        const uploadId = request.headers.get("X-Upload-Id") || "";
        const partNumber = Number(request.headers.get("X-Part-Number"));
        if (!key.startsWith("rickstreams/") || !uploadId || !Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
          return reply({ error: "Invalid upload part details." }, 400, origin);
        }
        const part = await env.RICKSTREAMS_BUCKET.resumeMultipartUpload(key, uploadId).uploadPart(partNumber, request.body);
        return reply({ etag: part.etag, partNumber }, 200, origin);
      }

      if (url.pathname === "/upload/complete") {
        const body = await request.json();
        if (!String(body.key || "").startsWith("rickstreams/") || !body.uploadId || !Array.isArray(body.parts) || !body.parts.length) {
          return reply({ error: "Invalid completion details." }, 400, origin);
        }
        await env.RICKSTREAMS_BUCKET.resumeMultipartUpload(body.key, body.uploadId).complete(
          body.parts.map(part => ({ partNumber: Number(part.partNumber), etag: part.etag }))
        );
        return reply({
          key: body.key,
          mediaUrl: url.origin + "/media/" + encodeURIComponent(body.key)
        }, 200, origin);
      }

      if (url.pathname === "/upload/abort") {
        const body = await request.json();
        if (!String(body.key || "").startsWith("rickstreams/") || !body.uploadId) {
          return reply({ error: "Invalid abort details." }, 400, origin);
        }
        await env.RICKSTREAMS_BUCKET.resumeMultipartUpload(body.key, body.uploadId).abort();
        return reply({ ok: true }, 200, origin);
      }

      return reply({ error: "Unknown upload endpoint." }, 404, origin);
    } catch (error) {
      return reply({ error: error.message || "Upload failed." }, 403, origin);
    }
  }
};

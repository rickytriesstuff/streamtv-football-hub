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

async function requireCreatorOrOwner(request, env) {
  const user=await requireUser(request,env);
  if((user.email||"").toLowerCase()===(env.OWNER_EMAIL||"").toLowerCase()) return user;
  if(!env.CREATOR_SUBSCRIPTIONS) throw new Error("Creator verification is temporarily unavailable.");
  const creator=await env.CREATOR_SUBSCRIPTIONS.get("creator:"+user.localId,"json");
  if(!creator || creator.status!=="active") throw new Error("An active, verified creator subscription is required to upload.");
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
    scope:"https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/identitytoolkit",
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
  if(!r.ok) {
    const detail=(d.details||[]).map(x=>[x.issue,x.description].filter(Boolean).join(": ")).filter(Boolean).join(" | ");
    const debug=d.debug_id?" (PayPal debug ID: "+d.debug_id+")":"";
    throw new Error("PayPal API error "+r.status+": "+(d.name||"API request failed")+" - "+(d.message||"No message returned.")+(detail?" Details: "+detail:"")+debug);
  }
  return d;
}

function paypalLiveBase(){return "https://api-m.paypal.com";}
async function paypalLiveToken(env){
  if(!env.PAYPAL_LIVE_CLIENT_ID||!env.PAYPAL_LIVE_CLIENT_SECRET) throw new Error("Live PayPal credentials are missing. Add PAYPAL_LIVE_CLIENT_ID and PAYPAL_LIVE_CLIENT_SECRET in Cloudflare.");
  const auth=btoa(env.PAYPAL_LIVE_CLIENT_ID+":"+env.PAYPAL_LIVE_CLIENT_SECRET);
  const r=await fetch(paypalLiveBase()+"/v1/oauth2/token",{method:"POST",headers:{Authorization:"Basic "+auth,"Content-Type":"application/x-www-form-urlencoded"},body:"grant_type=client_credentials"});
  const d=await r.json();if(!r.ok||!d.access_token)throw new Error("PayPal Live authentication failed: "+(d.error_description||d.error||r.status));
  return d.access_token;
}
async function paypalLiveRequest(env,path,method="GET",body=null){
  const token=await paypalLiveToken(env);
  const r=await fetch(paypalLiveBase()+path,{method,headers:{Authorization:"Bearer "+token,"Content-Type":"application/json",Prefer:"return=representation"},...(body?{body:JSON.stringify(body)}:{})});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){const detail=(d.details||[]).map(x=>[x.issue,x.description].filter(Boolean).join(": ")).filter(Boolean).join(" | ");const debug=d.debug_id?" (PayPal debug ID: "+d.debug_id+")":"";throw new Error("PayPal Live API error "+r.status+": "+(d.name||"API request failed")+" - "+(d.message||"No message returned.")+(detail?" Details: "+detail:"")+debug);}
  return d;
}
async function setupPaypalLivePlan(env){
  if(!env.CREATOR_SUBSCRIPTIONS)throw new Error("Creator subscriptions KV binding is missing.");
  const existing=await env.CREATOR_SUBSCRIPTIONS.get("paypal:live:plan_id");
  if(existing){const current=await paypalLiveRequest(env,"/v1/billing/plans/"+encodeURIComponent(existing));if(current.status!=="ACTIVE")throw new Error("Saved Live plan is not active. Status: "+(current.status||"unknown"));return {productId:current.product_id,planId:current.id,status:current.status,reused:true,mode:"live"};}
  const product=await paypalLiveRequest(env,"/v1/catalogs/products","POST",{name:"RickStreams Creator Membership",description:"Monthly creator membership for RickStreams",type:"SERVICE",category:"SOFTWARE"});
  const plan=await paypalLiveRequest(env,"/v1/billing/plans","POST",{product_id:product.id,name:"RickStreams Creator Monthly",description:"RickStreams creator membership, billed monthly",billing_cycles:[{frequency:{interval_unit:"MONTH",interval_count:1},tenure_type:"REGULAR",sequence:1,total_cycles:0,pricing_scheme:{fixed_price:{value:"1.99",currency_code:"USD"}}}],payment_preferences:{auto_bill_outstanding:true,setup_fee_failure_action:"CANCEL",payment_failure_threshold:1}});
  let current=plan;
  if(plan.status!=="ACTIVE"){if(plan.status!=="CREATED"&&plan.status!=="INACTIVE")throw new Error("New Live plan has unexpected status: "+plan.status);await paypalLiveRequest(env,"/v1/billing/plans/"+encodeURIComponent(plan.id)+"/activate","POST",{});current=await paypalLiveRequest(env,"/v1/billing/plans/"+encodeURIComponent(plan.id));}
  if(current.status!=="ACTIVE")throw new Error("PayPal Live plan activation failed. Status: "+(current.status||"unknown"));
  await env.CREATOR_SUBSCRIPTIONS.put("paypal:live:plan_id",current.id);
  return {productId:current.product_id||product.id,planId:current.id,status:current.status,reused:false,mode:"live"};
}
async function createPaypalLiveSubscription(request,env,user){
  const planId=await env.CREATOR_SUBSCRIPTIONS.get("paypal:live:plan_id");
  if(!planId)throw new Error("The PayPal Live creator plan has not been configured. Ask the site owner to set it up first.");
  const base="https://rickstreams.site";
  const sub=await paypalLiveRequest(env,"/v1/billing/subscriptions","POST",{plan_id:planId,custom_id:user.localId,application_context:{brand_name:"RickStreams",locale:"en-US",user_action:"SUBSCRIBE_NOW",shipping_preference:"NO_SHIPPING",return_url:base+"/?creator_payment=return",cancel_url:base+"/?creator_payment=cancel"}});
  const approve=(sub.links||[]).find(x=>x.rel==="approve")?.href;
  if(!approve)throw new Error("PayPal Live did not return an approval link.");
  await env.CREATOR_SUBSCRIPTIONS.put("subscription:"+sub.id,JSON.stringify({uid:user.localId,status:sub.status||"APPROVAL_PENDING",createdAt:Date.now(),mode:"live"}));
  return {subscriptionId:sub.id,approvalUrl:approve,status:sub.status,mode:"live"};
}
async function handlePaypalLiveWebhook(request,env){
  if(!env.PAYPAL_LIVE_WEBHOOK_ID)throw new Error("PAYPAL_LIVE_WEBHOOK_ID is not configured in Cloudflare yet.");
  const event=await request.json(),h=request.headers;
  const verification=await paypalLiveRequest(env,"/v1/notifications/verify-webhook-signature","POST",{auth_algo:h.get("paypal-auth-algo"),cert_url:h.get("paypal-cert-url"),transmission_id:h.get("paypal-transmission-id"),transmission_sig:h.get("paypal-transmission-sig"),transmission_time:h.get("paypal-transmission-time"),webhook_id:env.PAYPAL_LIVE_WEBHOOK_ID,webhook_event:event});
  if(verification.verification_status!=="SUCCESS")throw new Error("PayPal Live webhook signature verification failed.");
  const resource=event.resource||{};
  const subscriptionId=resource.billing_agreement_id||resource.subscription_id||((event.event_type||"").startsWith("BILLING.SUBSCRIPTION.")?resource.id:null);
  const mapping=subscriptionId?await env.CREATOR_SUBSCRIPTIONS.get("subscription:"+subscriptionId,"json"):null;
  const uid=resource.custom_id||mapping?.uid;
  if(!uid)return {received:true,ignored:true};
  const active=["BILLING.SUBSCRIPTION.ACTIVATED","PAYMENT.SALE.COMPLETED"];
  const inactive=["BILLING.SUBSCRIPTION.CANCELLED","BILLING.SUBSCRIPTION.SUSPENDED","BILLING.SUBSCRIPTION.EXPIRED","BILLING.SUBSCRIPTION.PAYMENT.FAILED","PAYMENT.SALE.REVERSED","PAYMENT.SALE.REFUNDED"];
  if(active.includes(event.event_type)){await env.CREATOR_SUBSCRIPTIONS.put("creator:"+uid,JSON.stringify({status:"active",subscriptionId,updatedAt:Date.now(),source:event.event_type,mode:"live"}));if(subscriptionId)await env.CREATOR_SUBSCRIPTIONS.put("subscription:"+subscriptionId,JSON.stringify({uid,status:"active",mode:"live"}));}
  else if(inactive.includes(event.event_type)){await env.CREATOR_SUBSCRIPTIONS.put("creator:"+uid,JSON.stringify({status:"inactive",subscriptionId,updatedAt:Date.now(),source:event.event_type,mode:"live"}));if(subscriptionId)await env.CREATOR_SUBSCRIPTIONS.put("subscription:"+subscriptionId,JSON.stringify({uid,status:"inactive",mode:"live"}));}
  return {received:true};
}

async function activatePaypalPlanSafely(env, planId) {
  const path="/v1/billing/plans/"+encodeURIComponent(planId);
  let current=await paypalRequest(env,path);
  if(current.status==="ACTIVE") return current;
  if(current.status!=="CREATED" && current.status!=="INACTIVE") {
    throw new Error("PayPal plan "+planId+" has status "+(current.status||"unknown")+". It cannot be activated in this state.");
  }
  try {
    await paypalRequest(env,path+"/activate","POST",{});
  } catch (error) {
    // PayPal can return PLAN_STATUS_INVALID if the plan became active between
    // the status read and activation request. Re-read before treating it as failure.
    current=await paypalRequest(env,path);
    if(current.status==="ACTIVE") return current;
    throw new Error(error.message+" Current PayPal plan status after re-check: "+(current.status||"unknown"));
  }
  current=await paypalRequest(env,path);
  if(current.status!=="ACTIVE") throw new Error("PayPal plan activation did not complete. Current plan status: "+(current.status||"unknown"));
  return current;
}
async function setupPaypalPlan(env){
  if(!env.CREATOR_SUBSCRIPTIONS) throw new Error("Cloudflare KV binding CREATOR_SUBSCRIPTIONS is missing.");
  const existingPlanId=await env.CREATOR_SUBSCRIPTIONS.get("paypal:plan_id");
  if(existingPlanId){
    const current=await activatePaypalPlanSafely(env,existingPlanId);
    return {productId:current.product_id,planId:current.id,status:current.status,reused:true};
  }
  const product=await paypalRequest(env,"/v1/catalogs/products","POST",{name:"RickStreams Creator Membership",description:"Monthly creator membership for RickStreams",type:"SERVICE",category:"SOFTWARE"});
  const plan=await paypalRequest(env,"/v1/billing/plans","POST",{product_id:product.id,name:"RickStreams Creator Monthly",description:"RickStreams creator membership, billed monthly",billing_cycles:[{frequency:{interval_unit:"MONTH",interval_count:1},tenure_type:"REGULAR",sequence:1,total_cycles:0,pricing_scheme:{fixed_price:{value:"1.99",currency_code:"USD"}}}],payment_preferences:{auto_bill_outstanding:true,setup_fee_failure_action:"CANCEL",payment_failure_threshold:1}});
  await env.CREATOR_SUBSCRIPTIONS.put("paypal:plan_id",plan.id);
  const current=await activatePaypalPlanSafely(env,plan.id);
  return {productId:current.product_id||product.id,planId:current.id||plan.id,status:current.status,reused:false};
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



async function deleteCreatorVideo(request,env,user,origin){
  const body=await request.json(),videoId=String(body.videoId||"");
  if(!/^[A-Za-z0-9_-]{8,32}$/.test(videoId)) throw new Error("Invalid video ID.");
  const {token,projectId}=await serviceAccessToken(env);
  if(projectId!=="streamtv-football-hub") throw new Error("Firebase service account belongs to the wrong project.");
  const path="streamtv/publicState/videos/"+videoId,current=await firebaseRead(path,token,true);
  if(!current.data) throw new Error("Video not found.");
  if(current.data.uploadedBy!==user.localId&&(user.email||"").toLowerCase()!==(env.OWNER_EMAIL||"").toLowerCase()) throw new Error("You can only delete your own videos.");
  const keyFor=value=>{try{const u=new URL(value);if(u.origin!==origin||!u.pathname.startsWith("/media/"))return "";const k=decodeURIComponent(u.pathname.slice(7));return k.startsWith("rickstreams/")&&!k.includes("..")?k:"";}catch{return "";}};
  const videoKey=keyFor(current.data.videoUrl||""),thumbKey=keyFor(current.data.thumbnailUrl||"");
  const result=await fetch(firebaseUrl(path),{method:"PUT",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json","If-Match":current.etag||"null_etag"},body:"null"});
  if(!result.ok) throw new Error("Could not delete the video record.");
  if(videoKey) await env.RICKSTREAMS_BUCKET.delete(videoKey);
  if(thumbKey) await env.RICKSTREAMS_BUCKET.delete(thumbKey);
  return {ok:true,videoId};
}
function validBitcoinAddress(value){
 const a=String(value||"").trim();if(a.length<26||a.length>62)return false;
 if(/^bc1/i.test(a)){if(a!==a.toLowerCase()&&a!==a.toUpperCase())return false;return /^bc1[ac-hj-np-z02-9]{20,59}$/i.test(a);}
 return /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(a);
}
async function creatorCanReceivePayout(env,user){const s=env.CREATOR_SUBSCRIPTIONS?await env.CREATOR_SUBSCRIPTIONS.get("creator:"+user.localId,"json"):null;if(s?.status!=="active"&&(user.email||"").toLowerCase()!==(env.OWNER_EMAIL||"").toLowerCase())throw new Error("An active creator subscription is required for Bitcoin payouts.");}
async function saveCreatorPaymentMethod(request,env,user){
 const body=await request.json(),address=String(body.bitcoinAddress||"").trim();if(!validBitcoinAddress(address))throw new Error("Enter a valid Bitcoin mainnet address starting with 1, 3 or bc1.");
 await creatorCanReceivePayout(env,user);const {token,projectId}=await serviceAccessToken(env);if(projectId!=="streamtv-football-hub")throw new Error("Firebase service account belongs to the wrong project.");
 const r=await fetch(firebaseUrl("streamtv/creatorPayoutMethods/"+user.localId),{method:"PUT",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({bitcoinAddress:address,currency:"BTC",network:"Bitcoin mainnet",updatedAt:Date.now(),status:"provided"})});
 if(!r.ok)throw new Error("Could not save your Bitcoin wallet address.");return {ok:true,bitcoinAddress:address,currency:"BTC"};
}
async function requestBitcoinPayout(request,env,user){
 await creatorCanReceivePayout(env,user);const {token,projectId}=await serviceAccessToken(env);if(projectId!=="streamtv-football-hub")throw new Error("Firebase service account belongs to the wrong project.");
 const method=await firebaseRead("streamtv/creatorPayoutMethods/"+user.localId,token);if(!method.data?.bitcoinAddress||!validBitcoinAddress(method.data.bitcoinAddress))throw new Error("Save a valid Bitcoin wallet address before requesting a payout.");
 const requestPath="streamtv/creatorPayoutRequests/"+user.localId,existing=await firebaseRead(requestPath,token,true);if(existing.data?.status==="pending")throw new Error("You already have a pending payout request.");
 const earningsPath="streamtv/creatorEarnings/"+user.localId;let reserved=false,amount=0;
 for(let i=0;i<8;i++){const c=await firebaseRead(earningsPath,token,true),d=c.data||{};const available=Math.round((Number(d.availableUsd)||0)*100)/100;if(available<25)throw new Error("You need at least $25.00 in available earnings.");amount=available;const next={...d,availableUsd:0,pendingUsd:Math.round(((Number(d.pendingUsd)||0)+amount)*100)/100};const w=await firebaseCompareAndSet(earningsPath,next,token,c.etag||"null_etag");if(w.ok){reserved=true;break;}if(w.status!==412)throw new Error("Could not reserve your payout balance.");}
 if(!reserved)throw new Error("Your earnings are being updated. Please try again.");
 const record={id:"btc_"+crypto.randomUUID().replace(/-/g,""),uid:user.localId,bitcoinAddress:method.data.bitcoinAddress,currency:"BTC",requestedUsd:amount,status:"pending",requestedAt:Date.now(),updatedAt:Date.now()};
 const saved=await fetch(firebaseUrl(requestPath),{method:"PUT",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify(record)});
 if(!saved.ok){for(let i=0;i<5;i++){const c=await firebaseRead(earningsPath,token,true),d=c.data||{},n={...d,availableUsd:Math.round(((Number(d.availableUsd)||0)+amount)*100)/100,pendingUsd:Math.max(0,Math.round(((Number(d.pendingUsd)||0)-amount)*100)/100)},u=await firebaseCompareAndSet(earningsPath,n,token,c.etag||"null_etag");if(u.ok)break;if(u.status!==412)break;}throw new Error("Could not save the request. Your balance restoration was attempted.");}
 return {ok:true,request:record,message:"Payout request submitted. It will be reviewed and paid manually in Bitcoin."};
}
async function manageBitcoinPayouts(request,env,owner){
 const {token,projectId}=await serviceAccessToken(env);if(projectId!=="streamtv-football-hub")throw new Error("Firebase service account belongs to the wrong project.");const body=await request.json(),root="streamtv/creatorPayoutRequests";
 if(body.action==="list"){const all=await firebaseRead(root,token),rows=[];for(const [uid,p] of Object.entries(all.data||{})){if(!p||typeof p!=="object")continue;const [profile,method]=await Promise.all([firebaseRead("streamtv/creatorProfiles/"+uid,token),firebaseRead("streamtv/creatorPayoutMethods/"+uid,token)]);rows.push({...p,uid,creatorName:profile.data?.displayName||"Creator",bitcoinAddress:method.data?.bitcoinAddress||p.bitcoinAddress||""});}return {requests:rows.sort((a,b)=>(b.requestedAt||0)-(a.requestedAt||0))};}
 if(body.action!=="update")throw new Error("Unknown payout admin action.");const uid=String(body.uid||""),status=String(body.status||""),txid=String(body.txid||"").trim(),btcAmount=String(body.btcAmount||"").trim();if(!/^[A-Za-z0-9_-]{1,128}$/.test(uid)||!["paid","rejected"].includes(status))throw new Error("Invalid payout update.");if(status==="paid"&&(!/^[0-9a-fA-F]{64}$/.test(txid)||!/^\d+(\.\d{1,8})?$/.test(btcAmount)||Number(btcAmount)<=0))throw new Error("Enter the BTC amount sent and a 64-character transaction ID.");
 const path=root+"/"+uid,current=await firebaseRead(path,token,true),p=current.data;if(!p||p.status!=="pending")throw new Error("This payout request is no longer pending.");const ep="streamtv/creatorEarnings/"+uid;let updatedBalance=false;
 for(let i=0;i<8;i++){const c=await firebaseRead(ep,token,true),d=c.data||{},pending=Math.max(0,Math.round(((Number(d.pendingUsd)||0)-Number(p.requestedUsd||0))*100)/100),n=status==="paid"?{...d,pendingUsd:pending,paidOutUsd:Math.round(((Number(d.paidOutUsd)||0)+Number(p.requestedUsd||0))*100)/100}:{...d,pendingUsd:pending,availableUsd:Math.round(((Number(d.availableUsd)||0)+Number(p.requestedUsd||0))*100)/100},w=await firebaseCompareAndSet(ep,n,token,c.etag||"null_etag");if(w.ok){updatedBalance=true;break;}if(w.status!==412)throw new Error("Could not update creator earnings.");}
 if(!updatedBalance)throw new Error("Creator earnings are busy. Refresh and retry.");const next={...p,status,updatedAt:Date.now(),...(status==="paid"?{txid,btcAmount,paidAt:Date.now(),paidBy:owner.localId}:{rejectedAt:Date.now(),rejectedBy:owner.localId})},save=await firebaseCompareAndSet(path,next,token,current.etag||"null_etag");if(!save.ok)throw new Error("Payout record changed during update. Refresh before retrying.");return {ok:true,payout:next};
}

async function publishVideoToFirebase(request, env, user, origin) {
  const body = await request.json();
  const title = String(body.title || "").trim().slice(0, 100);
  const description = String(body.description || "").trim().slice(0, 300);
  const orientation = body.orientation === "horizontal" ? "horizontal" : "vertical";
  const durationSeconds = Number(body.durationSeconds);
  if (!title) throw new Error("Please add a video title.");
  if (!Number.isFinite(durationSeconds) || durationSeconds <= 0) throw new Error("Invalid video duration.");
  if (orientation === "vertical" && durationSeconds > 120) throw new Error("Vertical videos cannot exceed 2 minutes.");
  if (orientation === "horizontal" && durationSeconds > 180) throw new Error("Horizontal videos cannot exceed 3 minutes.");
  const videoUrl = new URL(String(body.videoUrl || ""));
  if (videoUrl.origin !== origin || !videoUrl.pathname.startsWith("/media/")) throw new Error("Video must be uploaded to RickStreams storage first.");
  const videoKey = decodeURIComponent(videoUrl.pathname.slice(7));
  if (!videoKey.startsWith("rickstreams/videos/") || videoKey.includes("..")) throw new Error("Invalid video storage key.");
  const videoObject = await env.RICKSTREAMS_BUCKET.head(videoKey);
  if (!videoObject || !(videoObject.httpMetadata?.contentType || "").startsWith("video/")) throw new Error("Uploaded video was not found in storage.");
  let thumbnailUrl = "";
  if (body.thumbnailUrl) {
    const thumb = new URL(String(body.thumbnailUrl));
    if (thumb.origin !== origin || !thumb.pathname.startsWith("/media/")) throw new Error("Thumbnail must be uploaded to RickStreams storage.");
    const thumbKey = decodeURIComponent(thumb.pathname.slice(7));
    if (!thumbKey.startsWith("rickstreams/thumbnails/") || thumbKey.includes("..")) throw new Error("Invalid thumbnail storage key.");
    const thumbObject = await env.RICKSTREAMS_BUCKET.head(thumbKey);
    if (!thumbObject || !(thumbObject.httpMetadata?.contentType || "").startsWith("image/")) throw new Error("Uploaded thumbnail was not found in storage.");
    thumbnailUrl = thumb.href;
  }
  const videoId = String(body.videoId || "");
  if (!/^[A-Za-z0-9_-]{8,32}$/.test(videoId)) throw new Error("Invalid video record ID.");
  const { token, projectId } = await serviceAccessToken(env);
  if (projectId !== "streamtv-football-hub") throw new Error("Firebase service account belongs to the wrong project.");
  const record = {
    title, description, orientation, durationSeconds: Math.round(durationSeconds),
    videoUrl: videoUrl.href, thumbnailUrl, views: 0, eligibleViews: 0,
    earningsUsd: 0, createdAt: Date.now(), uploadedBy: user.localId,
    viewCountType: "verified_pending"
  };
  const dbPath = "streamtv/publicState/videos/" + encodeURIComponent(videoId);
  const write = await fetch(firebaseUrl(dbPath), {
    method: "PUT",
    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(record)
  });
  if (!write.ok) {
    const detail = await write.text().catch(() => "");
    const hint = detail.includes("PERMISSION_DENIED") ? " Firebase denied the service account. Grant it the Firebase Realtime Database Admin role in Google Cloud IAM, then retry." : "";
    throw new Error("Firebase publishing failed (" + write.status + "): " + detail.slice(0, 350) + hint);
  }
  const verify = await firebaseRead(dbPath, token);
  if (!verify.data || verify.data.uploadedBy !== user.localId) throw new Error("Firebase accepted the publish request but the video record could not be verified.");
}

function firebaseUrl(path, token) {
  return "https://streamtv-football-hub-default-rtdb.firebaseio.com/" + path + ".json" + (token ? "?access_token=" + encodeURIComponent(token) : "");
}
async function firebaseRead(path, token, withEtag=false) {
  const headers = {"Authorization":"Bearer "+token};
  if (withEtag) headers["X-Firebase-ETag"]="true";
  const response = await fetch(firebaseUrl(path), {headers});
  const raw = await response.text();
  if (!response.ok) throw new Error("Firebase read failed ("+response.status+"): "+raw.slice(0,250));
  return {data:raw ? JSON.parse(raw) : null, etag:response.headers.get("ETag")};
}
async function firebaseCompareAndSet(path, value, token, etag) {
  return fetch(firebaseUrl(path), {
    method:"PUT",
    headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json","If-Match":etag},
    body:JSON.stringify(value)
  });
}
async function firebaseAdminHealth(env) {
  const {token,projectId}=await serviceAccessToken(env);
  if(projectId!=="streamtv-football-hub") throw new Error("Firebase service account belongs to the wrong project: "+projectId);
  const read=await firebaseRead("streamtv/publicState/videos",token);
  const probePath="streamtv/_workerHealth/"+crypto.randomUUID();
  const probe=await fetch(firebaseUrl(probePath),{method:"PUT",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({at:Date.now(),service:"rickstreams-worker"})});
  if(!probe.ok){const detail=await probe.text().catch(()=>"");throw new Error("Firebase service account can read the database but cannot write: "+probe.status+" "+detail.slice(0,250)+". Grant the service account Firebase Realtime Database Admin access in Google Cloud IAM.");}
  const cleanup=await fetch(firebaseUrl(probePath),{method:"DELETE",headers:{"Authorization":"Bearer "+token}});
  if(!cleanup.ok) throw new Error("Firebase write test succeeded, but its temporary health-check record could not be removed.");
  return {ok:true,projectId,databaseRead:true,databaseWrite:true,visibleVideoRecords:read.data&&typeof read.data==="object"?Object.keys(read.data).length:0};
}

function firebaseUrl(path, token) {
  return "https://streamtv-football-hub-default-rtdb.firebaseio.com/" + path + ".json?access_token=" + encodeURIComponent(token);
}
async function firebaseRead(path, token, withEtag=false) {
  const response = await fetch(firebaseUrl(path, token), {headers: withEtag ? {"X-Firebase-ETag":"true"} : {}});
  const raw = await response.text();
  if (!response.ok) throw new Error("Firebase read failed ("+response.status+"): "+raw.slice(0,250));
  return {data:raw ? JSON.parse(raw) : null, etag:response.headers.get("ETag")};
}
async function firebaseCompareAndSet(path, value, token, etag) {
  return fetch(firebaseUrl(path, token), {
    method:"PUT",
    headers:{"Content-Type":"application/json","If-Match":etag},
    body:JSON.stringify(value)
  });
}
async function awardVerifiedView(env, session, viewerUid, sessionId) {
  const {token,projectId}=await serviceAccessToken(env);
  if(projectId!=="streamtv-football-hub") throw new Error("Firebase service account belongs to the wrong project.");
  const day=new Date().toISOString().slice(0,10);
  const eventId=("watch_"+String(sessionId||"")).replace(/[^A-Za-z0-9_-]/g,"_");
  const earningsPath="streamtv/creatorEarnings/"+session.creatorUid;
  let applied=false;
  for(let attempt=0;attempt<8;attempt++){
    const current=await firebaseRead(earningsPath,token,true);
    const data=current.data&&typeof current.data==="object"?current.data:{};
    const events=data.verifiedEvents&&typeof data.verifiedEvents==="object"?data.verifiedEvents:{};
    if(events[eventId]) return {awarded:false,reason:"already_counted"};
    const earnedMicros=Math.round((Number(data.earnedUsd)||0)*1000000)+450;
    const availableMicros=Math.round((Number(data.availableUsd)||0)*1000000)+450;
    const next={
      ...data,
      eligibleViews:(Number(data.eligibleViews)||0)+1,
      earnedUsd:earnedMicros/1000000,
      availableUsd:availableMicros/1000000,
      verifiedEvents:{...events,[eventId]:{videoId:session.videoId,viewerUid,day,earnedMicros:450,at:Date.now()}}
    };
    const write=await firebaseCompareAndSet(earningsPath,next,token,current.etag||"null_etag");
    if(write.ok){applied=true;break;}
    if(write.status!==412){const detail=await write.text().catch(()=>"");throw new Error("Could not update creator earnings ("+write.status+"): "+detail.slice(0,250));}
  }
  if(!applied) throw new Error("Creator earnings are busy. Please retry after a moment.");
  const videoPath="streamtv/publicState/videos/"+session.videoId;
  for(let attempt=0;attempt<5;attempt++){
    const current=await firebaseRead(videoPath,token,true);
    if(!current.data) break;
    const next={...current.data,eligibleViews:(Number(current.data.eligibleViews)||0)+1};
    const write=await firebaseCompareAndSet(videoPath,next,token,current.etag||"null_etag");
    if(write.ok) break;
    if(write.status!==412) break;
  }
  const analyticsPath="streamtv/analytics/videoViews/"+viewerUid+"/"+session.videoId+"/"+day;
  const analytics=await firebaseRead(analyticsPath,token,true);
  if(!analytics.data){
    await firebaseCompareAndSet(analyticsPath,{videoId:session.videoId,watchedSeconds:15,at:Date.now(),type:"15_second_playback_verified",verificationStatus:"verified"},token,analytics.etag||"null_etag");
  }
  return {awarded:true,eligibleViewsIncremented:true,rateUsdPerThousand:0.45,earnedUsd:0.00045};
}
async function startWatchSession(request,env,user){
  const body=await request.json();
  const videoId=String(body.videoId||"");
  if(!/^[A-Za-z0-9_-]{8,32}$/.test(videoId)) throw new Error("Invalid video ID.");
  const {token}=await serviceAccessToken(env);
  const videoPath="streamtv/publicState/videos/"+videoId;
  const result=await firebaseRead(videoPath,token,true);
  const video=result.data;
  if(!video||!video.videoUrl) throw new Error("This video is no longer available.");
  if(video.uploadedBy===user.localId) return {eligible:false,reason:"creator_self_view"};
  let viewCounted=false;
  for(let attempt=0;attempt<8;attempt++){
    const current=await firebaseRead(videoPath,token,true);
    if(!current.data) throw new Error("This video is no longer available.");
    const next={...current.data,views:(Number(current.data.views)||0)+1};
    const write=await firebaseCompareAndSet(videoPath,next,token,current.etag||"null_etag");
    if(write.ok){viewCounted=true;break;}
    if(write.status!==412){const detail=await write.text().catch(()=>"");throw new Error("Could not record video view ("+write.status+"): "+detail.slice(0,200));}
  }
  if(!viewCounted) throw new Error("Video view counter is busy. Please try again.");
  const sessionId=crypto.randomUUID();
  const session={
    uid:user.localId,videoId,creatorUid:String(video.uploadedBy||""),
    startedAt:Date.now(),lastHeartbeatAt:Date.now(),lastPosition:Number(body.currentTime)||0,
    watchedSeconds:0,awarded:false
  };
  if(!session.creatorUid) throw new Error("This video has no creator account.");
  await env.CREATOR_SUBSCRIPTIONS.put("watch:"+sessionId,JSON.stringify(session),{expirationTtl:300});
  return {sessionId,eligible:true,requiredSeconds:15};
}
async function heartbeatWatchSession(request,env,user){
  const body=await request.json();
  const sessionId=String(body.sessionId||"");
  const key="watch:"+sessionId;
  if(!/^[0-9a-f-]{36}$/i.test(sessionId)) throw new Error("Invalid watch session.");
  const session=await env.CREATOR_SUBSCRIPTIONS.get(key,"json");
  if(!session||session.uid!==user.localId) throw new Error("Watch session expired. Reopen the video to start again.");
  if(session.awarded) return {verified:true,awarded:false,reason:"already_processed"};
  const now=Date.now();
  const position=Number(body.currentTime);
  if(body.playing!==true||!Number.isFinite(position)||position<0){
    session.lastHeartbeatAt=now;
    session.lastPosition=Number.isFinite(position)?position:session.lastPosition;
    await env.CREATOR_SUBSCRIPTIONS.put(key,JSON.stringify(session),{expirationTtl:300});
    return {verified:false,watchedSeconds:session.watchedSeconds};
  }
  const elapsed=(now-session.lastHeartbeatAt)/1000;
  const delta=position-session.lastPosition;
  if(elapsed>=2.5&&elapsed<=12&&delta>=Math.max(0.5,elapsed*0.35)&&delta<=elapsed*1.8+1){
    session.watchedSeconds+=Math.min(elapsed,delta);
  }
  session.lastHeartbeatAt=now;
  session.lastPosition=position;
  if(session.watchedSeconds>=15){
    const result=await awardVerifiedView(env,session,user.localId,sessionId);
    session.awarded=true;
    await env.CREATOR_SUBSCRIPTIONS.put(key,JSON.stringify(session),{expirationTtl:300});
    return {verified:true,...result,watchedSeconds:session.watchedSeconds};
  }
  await env.CREATOR_SUBSCRIPTIONS.put(key,JSON.stringify(session),{expirationTtl:300});
  return {verified:false,watchedSeconds:Math.floor(session.watchedSeconds),remainingSeconds:Math.max(0,Math.ceil(15-session.watchedSeconds))};
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

    if (url.pathname === "/payments/paypal/live-webhook" && request.method === "POST") { try { const result=await handlePaypalLiveWebhook(request,env); return reply(result,200,origin); } catch(error) { return reply({error:error.message||"Live webhook processing failed."},400,origin); } }
    if (url.pathname === "/payments/paypal/webhook" && request.method === "POST") { try { const result=await handlePaypalWebhook(request,env); return reply(result,200,origin); } catch(error) { return reply({error:error.message||"Webhook processing failed."},400,origin); } }

    if (url.pathname === "/creator/status") { try { const user=await requireUser(request,env); const record=env.CREATOR_SUBSCRIPTIONS?await env.CREATOR_SUBSCRIPTIONS.get("creator:"+user.localId,"json"):null; return reply({status:record?.status||"inactive",creator:record||null},200,origin); } catch(error) { return reply({error:error.message},401,origin); } }

    if (!url.pathname.startsWith("/upload/") && url.pathname !== "/publish" && url.pathname !== "/video/delete" && url.pathname !== "/creator/payment-method" && url.pathname !== "/creator/payout/request" && url.pathname !== "/admin/bitcoin-payouts" && url.pathname !== "/admin/firebase-check" && url.pathname !== "/watch/start" && url.pathname !== "/watch/heartbeat" && url.pathname !== "/admin/migrate-existing-accounts" && url.pathname !== "/admin/paypal/setup-plan" && url.pathname !== "/payments/paypal/create-subscription" && url.pathname !== "/admin/paypal/setup-live-plan" && url.pathname !== "/payments/paypal/create-live-subscription") {
      return reply({ ok: true, service: "RickStreams upload service" }, 200, origin);
    }

    try {
      if (url.pathname === "/admin/bitcoin-payouts") { const owner=await requireOwner(request,env); return reply(await manageBitcoinPayouts(request,env,owner),200,origin); }
       if (url.pathname === "/admin/firebase-check") { await requireOwner(request,env); return reply(await firebaseAdminHealth(env),200,origin); }
      if (request.method !== "POST") return reply({ error: "Method not allowed" }, 405, origin);

      if (url.pathname === "/payments/paypal/create-live-subscription") { const user=await requireUser(request,env); const result=await createPaypalLiveSubscription(request,env,user); return reply(result,200,origin); }

      if (url.pathname === "/admin/paypal/setup-live-plan") { await requireOwner(request,env); const result=await setupPaypalLivePlan(env); return reply({ok:true,...result},200,origin); }

      if (url.pathname === "/payments/paypal/create-subscription") {
        const user = await requireUser(request, env);
        const result = await createPaypalSubscription(request, env, user);
        return reply(result, 200, origin);
      }

      if (url.pathname === "/admin/paypal/setup-plan") {
        await requireOwner(request, env); const result=await setupPaypalPlan(env); return reply({ok:true,...result},200,origin); }

      if (url.pathname === "/admin/migrate-existing-accounts") {
        await requireOwner(request, env);
        const result = await migrateExistingAccounts(env);
        return reply({ ok:true, migrated:result.migrated, status:"grandfathered" }, 200, origin);
      }

      if (url.pathname.startsWith("/upload/") || url.pathname === "/publish") await requireCreatorOrOwner(request, env);

      if (url.pathname === "/publish") {
        const user = await requireUser(request, env);
        const result = await publishVideoToFirebase(request, env, user, url.origin);
        return reply(result, 200, origin);
      }

      if (url.pathname === "/video/delete") { const user=await requireUser(request,env); return reply(await deleteCreatorVideo(request,env,user,url.origin),200,origin); }
      if (url.pathname === "/creator/payment-method") { const user=await requireUser(request,env); return reply(await saveCreatorPaymentMethod(request,env,user),200,origin); }
      if (url.pathname === "/creator/payout/request") { const user=await requireUser(request,env); return reply(await requestBitcoinPayout(request,env,user),200,origin); }
      if (url.pathname === "/watch/start") { const user=await requireUser(request,env); return reply(await startWatchSession(request,env,user),200,origin); }
      if (url.pathname === "/watch/heartbeat") { const user=await requireUser(request,env); return reply(await heartbeatWatchSession(request,env,user),200,origin); }

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

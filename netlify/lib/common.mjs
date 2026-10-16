import {createHmac,createHash,timingSafeEqual,scryptSync,randomBytes,randomInt,createCipheriv,createDecipheriv} from 'node:crypto';
import {getStore} from '@netlify/blobs';
export const db=()=>getStore({name:'qm-logs',consistency:'strong'});
const secret=()=>{const s=process.env.TOKEN_SECRET;if(!s||s.length<32)throw new Error('TOKEN_SECRET missing or too short');return s};
export const sign=(p,ttl)=>{const body=Buffer.from(JSON.stringify({...p,exp:Math.floor(Date.now()/1000)+ttl})).toString('base64url');return body+'.'+createHmac('sha256',secret()).update(body).digest('base64url')};
export const verify=t=>{if(!t||typeof t!=='string')return null;const [body,sig]=t.split('.');if(!body||!sig)return null;const e=Buffer.from(createHmac('sha256',secret()).update(body).digest('base64url')),a=Buffer.from(sig);if(a.length!==e.length||!timingSafeEqual(a,e))return null;try{const p=JSON.parse(Buffer.from(body,'base64url').toString());return p.exp>Date.now()/1000?p:null}catch{return null}};
const sha=s=>createHash('sha256').update(String(s)).digest();
export const checkSecret=(input,plainName,hashName)=>{input=String(input??'').slice(0,200);if(!input)return false;const h=process.env[hashName];
 if(h){const [k,salt,hex]=h.split('$');if(k!=='scrypt'||!salt||!hex)return false;const d=scryptSync(input,Buffer.from(salt,'hex'),64),e=Buffer.from(hex,'hex');return d.length===e.length&&timingSafeEqual(d,e)}
 const p=process.env[plainName];return p?timingSafeEqual(sha(input),sha(p)):false};
export const json=(s,o,h={})=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...h}});
export const clean=(s,n)=>String(s??'').replace(/[\u0000-\u001f\u007f<>"`]/g,'').replace(/\s+/g,' ').trim().slice(0,n);
export const ipOf=(req,ctx)=>String(ctx?.ip||req.headers.get('x-nf-client-connection-ip')||(req.headers.get('x-forwarded-for')||'').split(',')[0]||'unknown').trim().slice(0,64);
export const uaOf=req=>clean(req.headers.get('user-agent'),140);
export const normId=s=>clean(s,24).toLowerCase().replace(/[^a-z0-9._-]/g,'');
export const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const rk=(kind,ip)=>`rl/${kind}/${ip.replace(/[^a-zA-Z0-9.:_-]/g,'_')}`;
export async function locked(kind,ip){const r=await db().get(rk(kind,ip),{type:'json'});return r&&r.until>Date.now()?Math.ceil((r.until-Date.now())/60000):0}
export async function fail(kind,ip,max,lockMin){const k=rk(kind,ip),r=(await db().get(k,{type:'json'}))||{n:0,until:0};r.n++;if(r.n>=max){r.until=Date.now()+lockMin*60000;r.n=0}await db().setJSON(k,r)}
export const clearFails=(kind,ip)=>db().delete(rk(kind,ip)).catch(()=>{});
export const getStudent=sid=>db().get('st/'+sid,{type:'json'});
export const putStudent=r=>db().setJSON('st/'+r.sid,r);
export async function isBlocked(sid){const r=await getStudent(sid);return !r||r.status!=='active'}
export const sha256hex=s=>createHash('sha256').update(String(s)).digest('hex');
const AL='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const genCode=()=>Array.from({length:12},()=>AL[randomInt(AL.length)]).join('').replace(/(.{4})(?=.)/g,'$1-');
export const normCode=s=>String(s??'').toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,40);
export const hashCode=c=>{const salt=randomBytes(16);return 'scrypt$'+salt.toString('hex')+'$'+scryptSync(normCode(c),salt,64).toString('hex')};
export const verifyCode=(c,h)=>{const [k,s,x]=String(h||'').split('$');if(k!=='scrypt'||!s||!x)return false;const d=scryptSync(normCode(c),Buffer.from(s,'hex'),64),e=Buffer.from(x,'hex');return d.length===e.length&&timingSafeEqual(d,e)};
const ek=()=>createHash('sha256').update('codekey:'+secret()).digest();
export const enc=t=>{const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',ek(),iv),ct=Buffer.concat([c.update(t,'utf8'),c.final()]);return [iv,c.getAuthTag(),ct].map(b=>b.toString('base64url')).join('.')};
export const dec=s=>{try{const [iv,tag,ct]=String(s).split('.').map(x=>Buffer.from(x,'base64url'));const d=createDecipheriv('aes-256-gcm',ek(),iv);d.setAuthTag(tag);return Buffer.concat([d.update(ct),d.final()]).toString('utf8')}catch{return null}};
export async function createStudent({name,sid,group,via}){if(await getStudent(sid))return null;const code=genCode();await putStudent({sid,name,group,hash:hashCode(code),status:'active',created:Date.now(),via,lastLogin:0});return code}
export async function listPrefix(prefix,limit=500){const l=await db().list({prefix});const keys=(l.blobs||[]).map(x=>x.key).slice(0,limit),out=[];for(let i=0;i<keys.length;i+=25){const r=await Promise.all(keys.slice(i,i+25).map(k=>db().get(k,{type:'json'}).catch(()=>null)));out.push(...r.filter(Boolean))}return out}
export async function record(ev){const ts=Date.now();await db().setJSON(`e/${new Date(ts).toISOString().slice(0,10)}/${String(ts).padStart(13,'0')}-${randomBytes(3).toString('hex')}`,{ts,...ev})}
export const cookieOf=req=>{const m=(req.headers.get('cookie')||'').match(/(?:^|;\s*)cj_session=([^;]+)/);return m?m[1]:''};
export const session=req=>{const p=verify(cookieOf(req));return p&&p.r==='s'?p:null};
export const COOKIE=(v,age)=>`cj_session=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
export const newSess=()=>randomBytes(5).toString('hex');

// Optional Telegram alert to the administrator (does nothing unless both variables are set)
export async function notify(text,origin){const tk=process.env.TELEGRAM_BOT_TOKEN,chat=process.env.TELEGRAM_CHAT_ID;if(!tk||!chat)return;
 try{const body={chat_id:chat,text:String(text).slice(0,900),disable_web_page_preview:true};if(origin)body.reply_markup={inline_keyboard:[[{text:'Open admin panel',url:origin+'/admin.html'}]]};
  await fetch('https://api.telegram.org/bot'+tk+'/sendMessage',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(4000)})}catch(e){console.error('notify failed',e.message)}}

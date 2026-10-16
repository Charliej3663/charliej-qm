import {json,ipOf,uaOf,clean,normId,sleep,checkSecret,locked,fail,clearFails,record,sign,verify,db,getStudent,putStudent,genCode,hashCode,enc,createStudent,listPrefix,notify} from '../lib/common.mjs';
export default async (req,ctx)=>{
 try{
  if(req.method!=='POST')return json(405,{error:'Method not allowed'});
  let b;try{b=await req.json()}catch{return json(400,{error:'Bad request'})}
  const ip=ipOf(req,ctx),ua=uaOf(req);
  if(b.action==='login'){
   const lk=await locked('a',ip);if(lk)return json(429,{error:`Locked for ${lk} more minute(s) after too many wrong attempts.`});
   if(!checkSecret(b.password,'ADMIN_PASSWORD','ADMIN_HASH')){await fail('a',ip,5,30);await record({e:'admin_fail',ip,ua});if(await locked('a',ip))await notify(`⚠️ Admin panel: 5 wrong passwords from ${ip}. That connection is locked for 30 minutes.`);await sleep(1500);return json(401,{error:'Wrong password.'})}
   await clearFails('a',ip);await record({e:'admin_login',ip,ua});await notify(`🔑 Admin panel signed in from ${ip}. If this was not you, change ADMIN_HASH and TOKEN_SECRET in Netlify now.`);
   return json(200,{token:sign({r:'a'},2*3600)});
  }
  const p=verify((req.headers.get('authorization')||'').replace(/^Bearer /,''));
  if(!p||p.r!=='a')return json(401,{error:'Admin session expired. Sign in again.'});
  const store=db(),act=async(e,sid,d)=>record({e,sid,ip,ua,d});
  if(b.action==='events'){
   const days=Math.min(14,Math.max(1,parseInt(b.days)||1)),since=Date.now()-days*864e5;let keys=[];
   for(let i=0;i<=days;i++){const d=new Date(Date.now()-i*864e5).toISOString().slice(0,10);const l=await store.list({prefix:`e/${d}/`});keys.push(...(l.blobs||[]).map(x=>x.key))}
   keys=[...new Set(keys)].sort().reverse().slice(0,2000);const out=[];
   for(let i=0;i<keys.length;i+=25){const r=await Promise.all(keys.slice(i,i+25).map(k=>store.get(k,{type:'json'}).catch(()=>null)));for(const e of r)if(e&&e.ts>=since)out.push(e)}
   out.sort((x,y)=>y.ts-x.ts);
   const students=(await listPrefix('st/')).map(({hash,...r})=>r),requests=(await listPrefix('req/',300)).map(({enc,ip,...r})=>({...r,ip})).sort((x,y)=>y.ts-x.ts);
   return json(200,{events:out,students,requests,now:Date.now()});
  }
  if(b.action==='add'){
   const name=clean(b.name,60),sid=normId(b.sid),group=clean(b.group,20);
   if(name.length<2||sid.length<3)return json(400,{error:'Enter a full name and a student ID (at least 3 characters).'});
   const code=await createStudent({name,sid,group,via:'admin'});if(!code)return json(409,{error:'This student ID is already registered. Use Reset code instead.'});
   await act('admin_add',sid);return json(200,{rows:[{name,sid,code}]});
  }
  if(b.action==='bulk'){
   const rows=[];for(const line of String(b.text||'').split('\n').slice(0,150)){const t=line.split(/[,\t;]/).map(x=>x.trim());if(t.length<2||!t[0])continue;
    const name=clean(t[0],60),sid=normId(t[1]),group=clean(t[2]||'',20);
    if(name.length<2||sid.length<3){rows.push({name,sid,error:'Invalid name or ID'});continue}
    const code=await createStudent({name,sid,group,via:'admin'});rows.push(code?{name,sid,code}:{name,sid,error:'Already registered'});if(code)await act('admin_add',sid)}
   return json(200,{rows});
  }
  if(b.action==='approve'||b.action==='reject'){
   const key=String(b.key||'').replace(/[^a-f0-9]/g,''),r=await store.get('req/'+key,{type:'json'});
   if(!r||r.status!=='pending')return json(404,{error:'This request is not pending any more.'});
   if(b.action==='reject'){r.status='rejected';await store.setJSON('req/'+key,r);await act('admin_reject',r.sid);return json(200,{ok:true})}
   const code=await createStudent({name:r.name,sid:r.sid,group:r.group,via:'request'});if(!code)return json(409,{error:'This student ID is already registered.'});
   r.status='approved';r.enc=enc(code);r.approved=Date.now();await store.setJSON('req/'+key,r);await act('admin_approve',r.sid);
   return json(200,{rows:[{name:r.name,sid:r.sid,code}]});
  }
  if(['revoke','restore','reset'].includes(b.action)){
   const sid=normId(b.sid),r=await getStudent(sid);if(!r)return json(404,{error:'Student not found.'});
   let rows;
   if(b.action==='revoke')r.status='revoked';else if(b.action==='restore')r.status='active';else{const code=genCode();r.hash=hashCode(code);rows=[{name:r.name,sid,code}]}
   await putStudent(r);await act('admin_'+b.action,sid);return json(200,{ok:true,rows});
  }
  return json(400,{error:'Unknown action'});
 }catch(e){console.error(e);return json(500,{error:'Server error'})}
};
export const config={path:'/api/admin'};

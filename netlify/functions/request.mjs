import {json,ipOf,uaOf,clean,normId,locked,fail,db,getStudent,record,sha256hex,dec,notify} from '../lib/common.mjs';
import {randomBytes} from 'node:crypto';
export default async (req,ctx)=>{
 try{
  if(req.method!=='POST')return json(405,{error:'Method not allowed'});
  let b;try{b=await req.json()}catch{return json(400,{error:'Bad request'})}
  const path=new URL(req.url).pathname,store=db();
  if(path==='/api/request-status'){
   const key=sha256hex(String(b.ticket||'')).slice(0,32),r=await store.get('req/'+key,{type:'json'});
   if(!r)return json(404,{error:'Request not found.'});
   if(r.status==='approved'&&r.enc){const code=dec(r.enc);r.enc=null;r.collected=Date.now();await store.setJSON('req/'+key,r);return json(200,{status:'approved',sid:r.sid,name:r.name,code})}
   return json(200,{status:r.status,sid:r.sid,name:r.name,collected:!!r.collected});
  }
  const ip=ipOf(req,ctx),ua=uaOf(req),lk=await locked('r',ip);
  if(lk)return json(429,{error:'Too many requests from this connection. Please try again tomorrow.'});
  const name=clean(b.name,60),sid=normId(b.sid),group=clean(b.group,20),note=clean(b.note,100);
  if(name.length<2||sid.length<3)return json(400,{error:'Please enter your full name and your student ID.'});
  if(await getStudent(sid))return json(409,{error:'This student ID is already registered. If you lost your code, ask your lecturer to reset it.'});
  const ix=await store.get('reqsid/'+sid,{type:'json'});
  if(ix){const old=await store.get('req/'+ix.key,{type:'json'});if(old&&old.status==='pending')return json(409,{error:'A request for this student ID is already waiting for approval.'})}
  const ticket=randomBytes(24).toString('base64url'),key=sha256hex(ticket).slice(0,32);
  await store.setJSON('req/'+key,{key,name,sid,group,note,ts:Date.now(),ip,ua,status:'pending'});
  await store.setJSON('reqsid/'+sid,{key});
  await fail('r',ip,5,1440);await record({e:'access_request',name,sid,ip,ua,d:{group}});
  await notify(`🆕 Access request\nName: ${name}\nStudent ID: ${sid}${group?'\nGroup: '+group:''}${note?'\nContact: '+note:''}\nTap below to approve or reject.`,new URL(req.url).origin);
  return json(200,{ticket});
 }catch(e){console.error(e);return json(500,{error:'Server error'})}
};
export const config={path:['/api/request','/api/request-status']};

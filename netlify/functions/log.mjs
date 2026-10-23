import {json,ipOf,uaOf,clean,session,isBlocked,record} from '../lib/common.mjs';
const OK=new Set(['app_open','review','test_start','test_finish','leave','slides']);
export default async (req,ctx)=>{
 try{
  if(req.method!=='POST')return json(405,{error:'Method not allowed'});
  const p=session(req);if(!p)return json(401,{error:'Please sign in again.'});
  if(await isBlocked(p.i))return json(403,{error:'Blocked'});
  const txt=await req.text();if(txt.length>3000)return json(413,{error:'Too large'});
  let b;try{b=JSON.parse(txt)}catch{return json(400,{error:'Bad request'})}
  if(!OK.has(b.e))return json(400,{error:'Unknown event'});
  const d={};for(const [k,v] of Object.entries(b.d&&typeof b.d==='object'?b.d:{}).slice(0,12)){const key=clean(k,20);if(typeof v==='number'&&isFinite(v))d[key]=v;else if(typeof v==='string'||typeof v==='boolean')d[key]=typeof v==='string'?clean(v,80):v}
  await record({e:b.e,name:p.n,sid:p.i,sess:p.s,ip:ipOf(req,ctx),ua:uaOf(req),d});
  return json(200,{ok:true});
 }catch(e){console.error(e);return json(500,{error:'Server error'})}
};
export const config={path:'/api/log'};

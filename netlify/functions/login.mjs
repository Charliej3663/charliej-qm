import {json,ipOf,uaOf,normId,sleep,locked,fail,clearFails,getStudent,putStudent,hashCode,verifyCode,record,sign,session,COOKIE,newSess} from '../lib/common.mjs';
let DUMMY=null;
export default async (req,ctx)=>{
 try{
  const path=new URL(req.url).pathname;
  if(path==='/api/me'){const p=session(req);return p?json(200,{ok:true,name:p.n}):json(401,{ok:false})}
  if(path==='/api/logout')return json(200,{ok:true},{'set-cookie':COOKIE('',0)});
  if(req.method!=='POST')return json(405,{error:'Method not allowed'});
  let b;try{b=await req.json()}catch{return json(400,{error:'Bad request'})}
  const ip=ipOf(req,ctx),ua=uaOf(req),lk=await locked('s',ip);
  if(lk)return json(429,{error:`Too many wrong attempts. Try again in ${lk} minute(s).`});
  const sid=normId(b.sid),code=String(b.code??'');
  if(sid.length<3||!code)return json(400,{error:'Enter your student ID and your personal code.'});
  const rec=await getStudent(sid);
  DUMMY=DUMMY||hashCode('dummy-value');
  const ok=rec?verifyCode(code,rec.hash):(verifyCode(code,DUMMY),false);
  if(!ok){await fail('s',ip,10,15);await record({e:'login_fail',sid,name:rec?rec.name:'(unknown ID)',ip,ua});await sleep(500);return json(401,{error:'Wrong student ID or code.'})}
  if(rec.status!=='active')return json(403,{error:'Your access has been blocked. Please contact your lecturer.'});
  await clearFails('s',ip);
  const sess=newSess(),token=sign({r:'s',n:rec.name,i:sid,s:sess},12*3600);
  rec.lastLogin=Date.now();await putStudent(rec);
  await record({e:'login',name:rec.name,sid,ip,ua,sess});
  return json(200,{ok:true,name:rec.name},{'set-cookie':COOKIE(token,12*3600)});
 }catch(err){console.error(err);return json(500,{error:'The server is not configured yet. Ask the administrator.'})}
};
export const config={path:['/api/login','/api/me','/api/logout']};

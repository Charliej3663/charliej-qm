import APP from '../lib/app-html.mjs';
import {session,isBlocked} from '../lib/common.mjs';
const back=()=>new Response(null,{status:302,headers:{location:'/','cache-control':'no-store'}});
export default async req=>{
 try{
  const p=session(req);if(!p||await isBlocked(p.i))return back();
  const who=JSON.stringify({n:p.n,i:p.i}).replace(/</g,'\\u003c');
  return new Response(APP.replace('/*WHO*/null/*END*/',()=>who),{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-robots-tag':'noindex, nofollow'}});
 }catch(e){console.error(e);return back()}
};
export const config={path:'/app'};

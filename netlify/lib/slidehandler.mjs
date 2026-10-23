import {session,isBlocked} from './common.mjs';
const no=(s,m)=>new Response(m,{status:s,headers:{'cache-control':'no-store','content-type':'text/plain'}});
export async function serve(req,M){
 try{
  const p=session(req);if(!p||await isBlocked(p.i))return no(401,'Please sign in again.');
  const u=new URL(req.url);
  if(u.pathname.endsWith('/pdf'))return new Response(Buffer.from(M.pdf,'base64'),{headers:{'content-type':'application/pdf','content-disposition':'inline; filename="QM-lecture.pdf"','cache-control':'private, max-age=3600','x-robots-tag':'noindex'}});
  const n=parseInt(u.searchParams.get('p'),10);if(!(n>=1&&n<=M.pages.length))return no(404,'No such slide');
  return new Response(Buffer.from(M.pages[n-1],'base64'),{headers:{'content-type':'image/jpeg','cache-control':'private, max-age=86400','x-robots-tag':'noindex'}});
 }catch(e){console.error(e);return no(500,'Server error')}
}

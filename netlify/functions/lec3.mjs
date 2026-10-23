import * as M from '../lib/lec3.mjs';
import {serve} from '../lib/slidehandler.mjs';
export default req=>serve(req,M);
export const config={path:['/api/lec3/slide','/api/lec3/pdf']};

import * as M from '../lib/lec4.mjs';
import {serve} from '../lib/slidehandler.mjs';
export default req=>serve(req,M);
export const config={path:['/api/lec4/slide','/api/lec4/pdf']};

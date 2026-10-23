import * as M from '../lib/lec6.mjs';
import {serve} from '../lib/slidehandler.mjs';
export default req=>serve(req,M);
export const config={path:['/api/lec6/slide','/api/lec6/pdf']};

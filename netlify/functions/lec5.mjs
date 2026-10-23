import * as M from '../lib/lec5.mjs';
import {serve} from '../lib/slidehandler.mjs';
export default req=>serve(req,M);
export const config={path:['/api/lec5/slide','/api/lec5/pdf']};

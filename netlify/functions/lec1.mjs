import * as M from '../lib/lec1.mjs';
import {serve} from '../lib/slidehandler.mjs';
export default req=>serve(req,M);
export const config={path:['/api/lec1/slide','/api/lec1/pdf']};

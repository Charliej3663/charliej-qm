import * as M from '../lib/lec2.mjs';
import {serve} from '../lib/slidehandler.mjs';
export default req=>serve(req,M);
export const config={path:['/api/lec2/slide','/api/lec2/pdf']};

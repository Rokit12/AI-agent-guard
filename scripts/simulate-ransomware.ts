// Ransomware drill: encrypts 40 fake statements inside sandbox/watched only. Run `npm run serve` first to watch it get caught.
import { simulateRansomware } from "../src/simulate.ts";
console.log(await simulateRansomware());

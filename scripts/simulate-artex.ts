// ARTEX-style intrusion drill: writes CloudTrail and egress records to sandbox/cloud/. Run `npm run serve` first.
import { simulateArtex } from "../src/simulate.ts";
console.log(await simulateArtex());

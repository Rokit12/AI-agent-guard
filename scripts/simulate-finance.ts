// Payment attack drill: writes an agent run log in sandbox/runs, event by event. Run `npm run serve` first.
import { simulateFinance } from "../src/simulate.ts";
console.log(await simulateFinance());

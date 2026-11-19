// carlcompliance.com. Static pages are served as they are; everything under
// /corbel/ first goes through Corbel's door (corbel_gate.js).
import { corbelGate } from "./corbel_gate.js";

export default {
  fetch(request, env) {
    return corbelGate(request, env, () => env.ASSETS.fetch(request));
  },
};

import { randomBytes } from "node:crypto";

import { KeyRing } from "@pallad/keyring";

export const KEY_RING = new KeyRing();
KEY_RING.addKey("k1", randomBytes(32));
KEY_RING.addKey("k2", randomBytes(32));

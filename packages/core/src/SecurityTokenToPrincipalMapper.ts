import { Maybe } from "@sweet-monads/maybe";

import { Token } from "./Token";
import { MaybePromise } from "./types";

export type SecurityTokenToPrincipalMapper = (token: Token) => MaybePromise<Maybe<unknown>>;

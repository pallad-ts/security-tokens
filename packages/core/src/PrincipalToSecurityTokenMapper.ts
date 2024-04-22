import { Maybe } from "@sweet-monads/maybe";

import { Token } from "./Token";
import { MaybePromise } from "./types";

export type PrincipalToSecurityTokenMapper = (principal: unknown) => MaybePromise<Maybe<Token>>;

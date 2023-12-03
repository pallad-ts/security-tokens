import {Token} from "./Token";
import {MaybePromise} from "./types";
import {Maybe} from "@sweet-monads/maybe";

export type SecurityTokenToPrincipalMapper<T> = (token: Token) => MaybePromise<Maybe<T>>

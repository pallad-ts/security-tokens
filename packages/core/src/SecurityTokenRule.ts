import {Token} from "./Token";

export type MaybePromise<T> = Promise<T> | T;

export abstract class SecurityTokenRule {
    abstract supportsToken(token: Token): boolean;

    abstract supportsParticipant(participant: any): boolean;

    abstract toParticipant(token: Token): MaybePromise<any>;

    abstract toToken(participant: any): MaybePromise<Token>;
}
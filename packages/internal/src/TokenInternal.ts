import {Token} from "@pallad/security-tokens";

export class TokenInternal<T = any> extends Token {
    constructor(readonly type: string, readonly payload?: T) {
        super();
    }
}
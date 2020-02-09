import {Token} from "@pallad/security-tokens";

export class TokenInternal extends Token {
    constructor(readonly type: string, readonly randomKey?: string) {
        super();
    }
}
import {SecurityTokenRule} from "./SecurityTokenRule";
import {Token} from "./Token";
import {errors} from "./errors";

export class SecurityTokens {
    private rules: Set<SecurityTokenRule> = new Set();

    addRule(rule: SecurityTokenRule): this {
        this.rules.add(rule);
        return this;
    }

    async toToken(participant: any): Promise<Token> {
        for (const rule of this.rules) {
            if (rule.supportsParticipant(participant)) {
                return rule.toToken(participant);
            }
        }
        throw errors.UNSUPPORTED_PARTICIPANT();
    }

    toParticipant(token: any): Promise<any> {
        for (const rule of this.rules) {
            if (rule.supportsToken(token)) {
                return rule.toParticipant(token);
            }
        }
        throw errors.UNSUPPORTED_TOKEN();
    }
}
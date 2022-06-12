import * as http from 'http';
import {Token} from "@pallad/security-tokens";

export class TokenFactory {
	private rules = new Set<TokenFactory.Rule>();

	registerRule(rule: TokenFactory.Rule): this {
		this.rules.add(rule);
		return this;
	}

	async fromHTTPRequest(request: TokenFactory.Request, defaultToken: Token = Token.NONE): Promise<Token> {
		for (const rule of this.rules) {
			const result = await rule(request);
			if (Token.isType(result)) {
				return result;
			}
		}
		return defaultToken;
	}

	static create(...rules: TokenFactory.Rule[]) {
		const factory = new TokenFactory();

		for (const rule of rules) {
			factory.registerRule(rule);
		}

		return factory;
	}
}

export namespace TokenFactory {
	export type Request = http.IncomingMessage;
	export type Result = Token | undefined;
	export type Rule = (x: Request) => Promise<Result> | Result;
}

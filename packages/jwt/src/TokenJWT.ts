import { Token } from "@pallad/security-tokens";

export class TokenJWT extends Token {
	constructor(readonly payload: string) {
		super();

		Object.freeze(this);
	}
}

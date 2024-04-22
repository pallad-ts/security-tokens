import { Token } from "@pallad/security-tokens";

export class SimpleToken extends Token {
	constructor(readonly value: any) {
		super();
	}

	static factory(x: any) {
		return new SimpleToken(x);
	}
}

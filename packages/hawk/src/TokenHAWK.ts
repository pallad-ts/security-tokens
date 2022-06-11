import {Token} from '@pallad/security-tokens';

export class TokenHAWK extends Token {
	constructor(readonly user: string) {
		super();
	}
}


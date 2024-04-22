import { PrincipalToSecurityTokenMapper } from "./PrincipalToSecurityTokenMapper";
import { Token } from "./Token";
import { errors } from "./errors";

export class PrincipalToSecurityTokenFactory {
	#mapperList: Set<PrincipalToSecurityTokenMapper> = new Set();

	addMapper(mapper: PrincipalToSecurityTokenMapper): this {
		this.#mapperList.add(mapper);
		return this;
	}

	async toToken(principal: unknown): Promise<Token> {
		for (const mapper of this.#mapperList) {
			const result = await mapper(principal);
			if (result.isJust()) {
				return result.unwrap();
			}
		}
		throw errors.UNSUPPORTED_TOKEN.create();
	}
}

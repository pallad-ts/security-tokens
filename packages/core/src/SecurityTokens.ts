import {errors} from "./errors";
import {SecurityTokenToPrincipalMapper} from "./SecurityTokenToPrincipalMapper";
import {Token} from "./Token";

export class SecurityTokens<T> {
	#rules: Set<SecurityTokenToPrincipalMapper<T>> = new Set();
	#defaultPrincipal?: T;

	addMapper(rule: SecurityTokenToPrincipalMapper<T>): this {
		this.#rules.add(rule);
		return this;
	}

	useDefaultPrincipal(defaultPrincipal: T): this {
		this.#defaultPrincipal = defaultPrincipal;
		return this;
	}

	async toPrincipal(token: Token): Promise<T> {
		for (const mapper of this.#rules) {
			const result = await mapper(token);
			if (result.isJust()) {
				return result.unwrap();
			}
		}

		if (this.#defaultPrincipal) {
			return this.#defaultPrincipal;
		}
		throw errors.UNSUPPORTED_TOKEN.create();
	}

	createObtainPrincipal() {
		let called = false;
		let result: Promise<T> | undefined;
		return async (token: Token) => {
			if (called) {
				return result!;
			}
			called = true;
			result = this.toPrincipal(token);
			return result;
		};
	}
}

import { SecurityTokenToPrincipalMapper } from "./SecurityTokenToPrincipalMapper";
import { Token } from "./Token";
import { errors } from "./errors";

export class SecurityTokenToPrincipalFactory {
	#mapperList: Set<SecurityTokenToPrincipalMapper> = new Set();
	#defaultPrincipal?: unknown;

	addMapper(mapper: SecurityTokenToPrincipalMapper): this {
		this.#mapperList.add(mapper);
		return this;
	}

	useDefaultPrincipal(defaultPrincipal: unknown): this {
		this.#defaultPrincipal = defaultPrincipal;
		return this;
	}

	async toPrincipal(token: Token): Promise<unknown> {
		for (const mapper of this.#mapperList) {
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
		let result: Promise<unknown> | undefined;
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

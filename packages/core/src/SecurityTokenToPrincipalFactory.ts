import { SecurityTokenToPrincipalMapper } from "./SecurityTokenToPrincipalMapper";
import { Token } from "./Token";
import { errors } from "./errors";

export class SecurityTokenToPrincipalFactory<T> {
	#mapperList: Set<SecurityTokenToPrincipalMapper<T>> = new Set();
	#defaultPrincipal?: T;

	addMapper(mapper: SecurityTokenToPrincipalMapper<T>): this {
		this.#mapperList.add(mapper);
		return this;
	}

	useDefaultPrincipal(defaultPrincipal: T): this {
		this.#defaultPrincipal = defaultPrincipal;
		return this;
	}

	async toPrincipal(token: Token): Promise<T> {
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

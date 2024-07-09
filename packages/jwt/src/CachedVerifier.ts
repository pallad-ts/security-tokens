import { Either, fromPromise } from "@sweet-monads/either";
import { JwtPayload } from "jsonwebtoken";
import { LRUCache } from "lru-cache";
import * as is from "predicates";

import { SecurityTokenError } from "@pallad/security-tokens";

import { JWT } from "./JWT";
import { JWTVerifier } from "./JWTVerifier";

function getCurrentTimestamp() {
	return Math.floor(Date.now() / 1000);
}

export class CachedVerifier<T extends JwtPayload> {
	#options: CachedVerifier.Options;
	#verifier: JWTVerifier;
	#cache: LRUCache<string, Either<SecurityTokenError, JWT<T>>>;

	constructor(
		verifier: JWTVerifier,
		cache: LRUCache<string, Either<SecurityTokenError, JWT<T>>>,
		options: CachedVerifier.Options
	) {
		this.#verifier = verifier;
		this.#options = options;
		this.#cache = cache;
	}

	async verify(token: string): Promise<JWT<T>> {
		const cacheResult = this.#cache.get(token, { allowStale: false });
		if (cacheResult) {
			if (cacheResult.isLeft()) {
				throw cacheResult.value;
			}
			return cacheResult.value;
		}

		const result = await fromPromise<SecurityTokenError, JWT<T>>(
			this.#verifier.verify<T>(token, this.#options.verifyOptions)
		);

		if (result.isRight()) {
			const timestamp = getCurrentTimestamp();
			const data = result.value as JWT<any>;
			const age = data.payload?.exp - timestamp;
			if (age > 0) {
				this.#cache.set(token, result, { ttl: age * 1000 });
			}
			return result.value;
		}

		const shouldCacheError = this.isCacheableError(result.value);
		if (shouldCacheError) {
			this.#cache.set(token, result);
		}
		throw result.value;
	}

	private isCacheableError(err: Error) {
		const cacheError = this.#options?.cacheError ?? false;

		if (is.bool(cacheError)) {
			return cacheError;
		}

		return cacheError(err);
	}
}

export namespace CachedVerifier {
	export interface Options {
		verifyOptions: JWTVerifier.VerifyOptions;
		/**
		 * Whether to cache errors.
		 * If a function is provided, it will be called with the error that occurred and boolean response from it indicates whether it is suppose to be cached.
		 */
		cacheError?: boolean | ((err: Error) => boolean);
	}
}

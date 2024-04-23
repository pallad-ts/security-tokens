import { Either, fromPromise } from "@sweet-monads/either";
import { JwtPayload } from "jsonwebtoken";
// eslint-disable-next-line @typescript-eslint/naming-convention
import { LRUCache } from "lru-cache";
import * as is from "predicates";

import { SecurityTokenError } from "@pallad/security-tokens";

import { JWT } from "./JWT";
import { JWTHelper } from "./JWTHelper";

function getCurrentTimestamp() {
	return Math.floor(Date.now() / 1000);
}

export class CachedVerifier<T extends JwtPayload = any> {
	constructor(private options: CachedVerifier.Options<T>) {}

	async verify(token: string): Promise<JWT<T>> {
		const cacheResult = this.options.cache.get(token, { allowStale: false });
		if (cacheResult) {
			if (cacheResult.isLeft()) {
				throw cacheResult.value;
			}
			return cacheResult.value;
		}

		const result = await fromPromise<SecurityTokenError, JWT<T>>(
			this.options.helper.verify<T>(token, this.options.verifyOptions)
		);

		if (result.isRight()) {
			const timestamp = getCurrentTimestamp();
			const data = result.value as any;
			const age = data.exp - timestamp;
			if (age > 0) {
				this.options.cache.set(token, result, { ttl: age });
			}
			return result.value;
		}

		const shouldCacheError = this.isCacheableError(result.value);
		if (shouldCacheError) {
			this.options.cache.set(token, result);
		}
		throw result.value;
	}

	private isCacheableError(err: Error) {
		const cacheError = this.options.options?.cacheError ?? false;

		if (is.bool(cacheError)) {
			return cacheError;
		}

		return cacheError(err);
	}
}

export namespace CachedVerifier {
	export interface Options<T extends JwtPayload> {
		helper: JWTHelper;
		cache: LRUCache<string, Either<SecurityTokenError, JWT<T>>>;
		verifyOptions: JWTHelper.VerifyOptions;
		options?: {
			cacheError?: boolean | ((err: Error) => boolean);
		};
	}
}

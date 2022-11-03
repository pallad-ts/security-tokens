import {JWTHelper} from "./JWTHelper";
import LRUCache = require("lru-cache");
import {SecurityTokenError} from "@pallad/security-tokens";
import * as is from 'predicates';
import {Either, right, left} from '@sweet-monads/either';

function getCurrentTimestamp() {
	return Math.floor(Date.now() / 1000);
}


export class CachedVerifier<T = any> {
	constructor(private options: CachedVerifier.Options<T>) {

	}

	async verify(token: string): Promise<T> {
		const cacheResult = this.options.cache.get(token, {allowStale: false});
		if (cacheResult) {
			if (cacheResult.isLeft()) {
				throw cacheResult.value;
			}
			return cacheResult.value;
		}

		const result = await this.options.helper.verify(token, this.options.verifyOptions)
			.then(x => right(x as T))
			.catch(left)

		if (result.isRight()) {
			const timestamp = getCurrentTimestamp();
			const data = result.value as any;
			const age = data.exp - timestamp;
			if (age > 0) {
				this.options.cache.set(token, result, {ttl: age})
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
	export interface Options<T> {
		helper: JWTHelper;
		cache: LRUCache<string, Either<SecurityTokenError, T>>;
		verifyOptions: JWTHelper.VerifyOptions,
		options?: {
			cacheError?: boolean | ((err: Error) => boolean)
		}
	}
}

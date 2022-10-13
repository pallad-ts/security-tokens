import {JWTHelper} from "./JWTHelper";
import LRUCache = require("lru-cache");
import {Either} from "monet";
import {SecurityTokenError} from "@pallad/security-tokens";
import * as is from 'predicates';

function getCurrentTimestamp() {
	return Math.floor(Date.now() / 1000);
}

export class CachedVerifier<T = any> {
	constructor(private options: CachedVerifier.Options<T>) {

	}

	async verify(token: string): Promise<T> {
		const cacheResult = this.options.cache.get(token, {allowStale: false});
		if (cacheResult) {
			return cacheResult.cata(e => {
				throw e
			}, x => x);
		}

		const result = await Either.fromPromise<T, SecurityTokenError>(
			this.options.helper.verify(token, this.options.verifyOptions)
		);

		if (result.isRight()) {
			const timestamp = getCurrentTimestamp();
			const data = result.right() as any;
			const age = data.exp - timestamp;
			if (age > 0) {
				this.options.cache.set(token, result, {ttl: age})
			}
			return result.right();
		}

		const shouldCacheError = this.isCacheableError(result.left());
		if (shouldCacheError) {
			this.options.cache.set(token, result);
		}
		throw result.left();
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

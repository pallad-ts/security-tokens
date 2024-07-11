import { VerifyOptions as _VerifyOptions, verify, Algorithm, JwtPayload } from "jsonwebtoken";
import { promisify } from "util";

import { CommonOptions } from "./CommonOptions";
import { JWT } from "./JWT";
import { errors } from "./errors";

export class JWTVerifier {
	#options: CommonOptions;

	constructor(options: CommonOptions.FromUser) {
		this.#options = CommonOptions.computeFromUser(options);
	}

	get algorithm() {
		return this.#options.algorithm;
	}

	async verify<T extends JwtPayload>(token: string, options: JWTVerifier.VerifyOptions = {}) {
		try {
			return await promisify<string, any, _VerifyOptions, JWT<T>>(verify)(
				token,
				this.#getSecretKeyForHeader.bind(this),
				{
					...options,
					algorithms: [this.#options.algorithm],
					complete: true,
				}
			);
		} catch (e: any) {
			switch (true) {
				case e.name === "TokenExpiredError":
					throw errors.EXPIRED.create();

				case e.name === "NotBeforeError":
					throw errors.NOT_VALID_BEFORE.create();

				case /secret or public key callback/.test(e.message):
					throw errors.INVALID_KEY_ID.create();

				case /malformed/.test(e.message):
					throw errors.MALFORMED.create();

				case /subject invalid/.test(e.message):
					throw errors.INVALID_SUBJECT.create();
			}
			throw e;
		}
	}

	#getSecretKeyForHeader(header: any, callback: (error?: Error, key?: Buffer) => void) {
		if (!header.kid) {
			callback(errors.INVALID_KEY_ID.create());
			return;
		}

		Promise.resolve(this.#options.secretProvider(header.kid))
			.then(key => {
				if (key) {
					callback(undefined, key.getValue());
				} else {
					callback(errors.INVALID_KEY_ID.create());
				}
			})
			.catch(callback);
	}
}

export namespace JWTVerifier {
	export type VerifyOptions = Omit<_VerifyOptions, "algorithms">;
}

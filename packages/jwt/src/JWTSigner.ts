import { SignOptions, SignOptions as _SignOptions, sign } from "jsonwebtoken";
import { Duration } from "luxon";
import { promisify } from "util";

import { CommonOptions } from "./CommonOptions";
import { errors } from "./errors";

export class JWTSigner {
	#options: CommonOptions;

	constructor(options: CommonOptions.FromUser) {
		this.#options = CommonOptions.computeFromUser(options);
	}

	get algorithm() {
		return this.#options.algorithm;
	}

	async sign<T>(data: T, { keyId, notBefore, expiresIn, ...options }: JWTSigner.SignOptions): Promise<string> {
		const key = await this.#options.secretProvider(keyId);

		if (!key) {
			throw errors.INVALID_KEY_ID.create();
		}

		const signOptions: _SignOptions = {
			...options,
			algorithm: this.#options.algorithm,
			keyid: keyId,
		};

		if (expiresIn) {
			signOptions.expiresIn = expiresIn.as("seconds");
		}
		if (notBefore) {
			signOptions.notBefore = notBefore.as("seconds");
		}

		return promisify<any, Buffer, SignOptions, string>(sign)(
			{
				...data,
			},
			key.getValue(),
			signOptions
		);
	}
}

export namespace JWTSigner {
	export interface SignOptions extends Omit<_SignOptions, "expiresIn" | "notBefore" | "algorithm" | "keyid"> {
		keyId: string;
		expiresIn?: Duration;
		notBefore?: Duration;
	}
}

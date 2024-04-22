import {
	Algorithm,
	Jwt,
	JwtPayload,
	sign,
	SignOptions,
	SignOptions as _SignOptions,
	verify,
	VerifyOptions as _VerifyOptions,
} from "jsonwebtoken";
import { Duration } from "luxon";
import { promisify } from "util";

import { KeyRing } from "@pallad/keyring";

import { JWT } from "./JWT";
import { errors } from "./errors";

export class JWTHelper {
	#keyRing: KeyRing;
	#algorithm: Algorithm;

	constructor(algorithm: Algorithm, keyRing: KeyRing) {
		this.#algorithm = algorithm;
		this.#keyRing = keyRing;
	}

	get algorithm() {
		return this.#algorithm;
	}

	sign<T>(data: T, options: JWTHelper.SignOptions = {}): Promise<string> {
		const key = this.#getKeyIdOrRandom(options.keyid);

		const { expiresIn, notBefore, ...restOptions } = options;
		const signOptions: _SignOptions = {
			...restOptions,
			algorithm: this.#algorithm,
			keyid: key.id,
		};

		if (options.expiresIn) {
			signOptions.expiresIn = options.expiresIn.as("seconds");
		}
		if (options.notBefore) {
			signOptions.notBefore = options.notBefore.as("seconds");
		}

		return promisify<any, string, SignOptions, string>(sign)(
			{
				...data,
			},
			key.key.getValue(),
			signOptions
		);
	}

	#getKeyIdOrRandom(keyId?: string) {
		if (!keyId) {
			return this.#keyRing.getRandomKey();
		}

		return this.#keyRing.assertEntryById(keyId);
	}

	async verify<T extends JwtPayload>(token: string, options: JWTHelper.VerifyOptions = {}) {
		try {
			return await promisify<string, any, _VerifyOptions, JWT<T>>(verify)(
				token,
				this.getPrivateKeyForHeader.bind(this),
				{
					...options,
					algorithms: [this.#algorithm],
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

	private getPrivateKeyForHeader(header: any, callback: (error?: Error, key?: string) => void) {
		if (!header.kid) {
			callback(errors.INVALID_KEY_ID.create());
			return;
		}

		const privateKey = this.#keyRing.getKeyById(header.kid);
		if (!privateKey) {
			callback(errors.INVALID_KEY_ID.create());
			return;
		}

		callback(undefined, privateKey.getValue());
	}
}

export namespace JWTHelper {
	export interface SignOptions extends Omit<_SignOptions, "expiresIn" | "notBefore" | "algorithm"> {
		expiresIn?: Duration;
		notBefore?: Duration;
	}

	export type VerifyOptions = Omit<_VerifyOptions, "algorithms">;
}

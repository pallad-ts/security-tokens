import {Secret} from "@pallad/secret";
import {server} from 'hawk';
import {webcrypto} from 'node:crypto';
import {errors} from "./errors";

export class CredentialsStorage {
	private credentials = new Map<string, CredentialsStorage.Credential>();
	private usernameIndex = new Set<string>();
	private keyIndex = new Set<string>();

	constructor(private algorithm: 'sha1' | 'sha256') {
	}

	registerCredential(id: string, key: Secret<string>, user: string) {
		if (this.usernameIndex.has(user)) {
			throw errors.USER_ALREADY_ALREADY_REGISTERED.format(user);
		}

		if (this.keyIndex.has(id)) {
			throw errors.CREDENTIAL_WITH_ID_ALREADY_REGISTERED.format(id);
		}

		this.credentials.set(id, {
			key,
			user
		});
		this.usernameIndex.add(user);

		return this;
	}

	retrieveCredentials(id: string): server.Credentials {
		if (!this.credentials.has(id)) {
			throw errors.NO_CREDENTIALS_FOUND.format(id);
		}
		const credential = this.credentials.get(id)!;

		return {key: credential.key.getValue(), user: credential.user, algorithm: this.algorithm};
	}
}

export namespace CredentialsStorage {
	export interface Credential {
		key: Secret<string>,
		user: string;
	}
}

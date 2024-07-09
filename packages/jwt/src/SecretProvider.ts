import { KeyRing } from "@pallad/keyring";
import { Secret } from "@pallad/secret";

export type SecretProvider = (keyId: string) => Promise<SecretProvider.Result> | SecretProvider.Result;
export namespace SecretProvider {
	export type Result = Secret<Buffer> | undefined;
}

export function createSecretProviderForKeyRing(keyRing: KeyRing): SecretProvider {
	return keyId => {
		return keyRing.getKeyById(keyId);
	};
}

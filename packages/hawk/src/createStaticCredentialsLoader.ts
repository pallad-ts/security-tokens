import {CredentialsLoader} from "./CredentialsLoader";
import {Credentials} from "./Credentials";

export function createStaticCredentialsLoader(algorithm: 'sha1' | 'sha256', credentials: Record<string, Credentials>): CredentialsLoader {
	return (id: string) => {
		const credential = credentials[id];
		if (credential === undefined) {
			return undefined;
		}

		return {key: credential.key.getValue(), user: credential.user, algorithm};
	}
}

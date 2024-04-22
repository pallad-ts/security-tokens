import { Credentials } from "./Credentials";
import { CredentialsLoader } from "./CredentialsLoader";

export function createStaticCredentialsLoader(
	algorithm: "sha1" | "sha256",
	credentials: Record<string, Credentials>
): CredentialsLoader {
	return (id: string) => {
		const credential = credentials[id];
		if (credential === undefined) {
			return undefined;
		}

		return { key: credential.key.getValue(), user: credential.user, algorithm };
	};
}

import { Algorithm } from "jsonwebtoken";

import { SecretProvider } from "./SecretProvider";

export interface CommonOptions {
	algorithm: Algorithm;
	secretProvider: SecretProvider;
}

export namespace CommonOptions {
	export const DEFAULT = {
		algorithm: "HS256",
	} satisfies Pick<CommonOptions, "algorithm">;

	export interface FromUser {
		algorithm?: Algorithm;
		secretProvider: SecretProvider;
	}

	export function computeFromUser(options: FromUser): CommonOptions {
		return {
			...DEFAULT,
			...options,
		};
	}
}

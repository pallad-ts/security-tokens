import { Secret } from "@pallad/secret";

export interface Credentials {
	key: Secret<string>;
	user: string;
}

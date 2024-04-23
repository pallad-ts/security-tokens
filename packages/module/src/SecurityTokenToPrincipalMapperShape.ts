import { SecurityTokenToPrincipalMapper } from "@pallad/security-tokens";

export interface SecurityTokenToPrincipalMapperShape {
	toPrincipal: SecurityTokenToPrincipalMapper;
}

export namespace SecurityTokenToPrincipalMapperShape {
	export function isType(value: unknown): value is SecurityTokenToPrincipalMapperShape {
		// eslint-disable-next-line no-null/no-null
		return typeof value === "object" && value !== null && "toPrincipal" in value;
	}
}

import { PrincipalToSecurityTokenMapper } from "@pallad/security-tokens";

export interface PrincipalToSecurityTokenMapperShape {
	toToken: PrincipalToSecurityTokenMapper;
}
export namespace PrincipalToSecurityTokenMapperShape {
	export function isType(value: unknown): value is PrincipalToSecurityTokenMapperShape {
		// eslint-disable-next-line no-null/no-null
		return typeof value === "object" && value !== null && "toToken" in value;
	}
}

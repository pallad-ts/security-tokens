import { Container, Definition, onActivation } from "@pallad/container";
import { Module as _Module, StandardActions } from "@pallad/modules";
import { SecurityTokenToPrincipalFactory, PrincipalToSecurityTokenFactory } from "@pallad/security-tokens";

import { PrincipalToSecurityTokenMapperShape } from "./PrincipalToSecurityTokenMapperShape";
import { References } from "./References";
import { SecurityTokenToPrincipalMapperShape } from "./SecurityTokenToPrincipalMapperShape";
import { principalToSecurityTokenMapperAnnotation } from "./principalToSecurityTokenMapperAnnotation";
import { securityTokenToPrincipalMapperAnnotation } from "./securityTokenToPrincipalMapperAnnotation";

export class Module extends _Module<{ container: Container }> {
	constructor() {
		super("@pallad/security-tokens/module");
	}

	init(): void {
		this.registerAction(StandardActions.INITIALIZATION, context => {
			context.container
				.registerDefinition(securityTokenToPrincipalFactoryDefinition())
				.registerDefinition(principalToSecurityTokenFactoryDefinition());
		});
	}
}

function securityTokenToPrincipalFactoryDefinition() {
	return Definition.useClass(
		SecurityTokenToPrincipalFactory,
		References.SECURITY_TOKEN_TO_PRINCIPAL_FACTORY
	).annotate(
		onActivation(async function (this: Container, service: SecurityTokenToPrincipalFactory) {
			const mapperList = await this.resolveByAnnotation<unknown, unknown>(
				securityTokenToPrincipalMapperAnnotation.predicate
			);
			for (const [mapper] of mapperList) {
				if (!SecurityTokenToPrincipalMapperShape.isType(mapper)) {
					throw new Error(
						"Principal to security token mapper does not implement PrincipalToSecurityTokenMapperShape interface"
					);
				}
				service.addMapper(mapper.toPrincipal.bind(mapper));
			}
			return service;
		})
	);
}

function principalToSecurityTokenFactoryDefinition() {
	return Definition.useClass(
		PrincipalToSecurityTokenFactory,
		References.PRINCIPAL_TO_SECURITY_TOKEN_FACTORY
	).annotate(
		onActivation(async function (this: Container, service: PrincipalToSecurityTokenFactory) {
			const mapperList = await this.resolveByAnnotation<unknown, unknown>(
				principalToSecurityTokenMapperAnnotation.predicate
			);

			for (const [mapper] of mapperList) {
				if (!PrincipalToSecurityTokenMapperShape.isType(mapper)) {
					throw new Error(
						"Principal to security token mapper does not implement PrincipalToSecurityTokenMapperShape interface"
					);
				}
				service.addMapper(mapper.toToken.bind(mapper));
			}
			return service;
		})
	);
}

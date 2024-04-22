import { Container, Definition, onActivation } from "@pallad/container";
import { Module as _Module, StandardActions } from "@pallad/modules";
import {
	SecurityTokenToPrincipalMapper,
	SecurityTokenToPrincipalFactory,
	PrincipalToSecurityTokenFactory,
} from "@pallad/security-tokens";

import { References } from "./References";
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
		onActivation(async function (this: Container, service: SecurityTokenToPrincipalFactory<any>) {
			const mapperList = await this.resolveByAnnotation<SecurityTokenToPrincipalMapper<any>, unknown>(
				securityTokenToPrincipalMapperAnnotation.predicate
			);
			for (const [mapper] of mapperList) {
				service.addMapper(mapper);
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
			const mapperList = await this.resolveByAnnotation<SecurityTokenToPrincipalMapper<any>, unknown>(
				securityTokenToPrincipalMapperAnnotation.predicate
			);
			for (const [mapper] of mapperList) {
				service.addMapper(mapper);
			}
			return service;
		})
	);
}

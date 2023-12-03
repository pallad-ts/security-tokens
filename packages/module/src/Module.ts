import {Module as _Module, StandardActions} from "@pallad/modules";
import {Container, onActivation} from "alpha-dic";
import {References} from "./References";
import {SecurityTokenToPrincipalMapper, SecurityTokens} from "@pallad/security-tokens";
import {PREDICATE} from "./securityTokenMapperAnnotation";

export class Module<T> extends _Module<{ container: Container }> {
	constructor() {
		super('@pallad/security-tokens/module');
	}

	init(): void {
		this.registerAction(StandardActions.INITIALIZATION, context => {
			context.container.definitionWithConstructor(References.SECURITY_TOKENS, SecurityTokens)
				.annotate(onActivation(async function (this: Container, service: SecurityTokens<T>) {
					for (const mapper of await this.getByAnnotation<SecurityTokenToPrincipalMapper<T>>(PREDICATE)) {
						service.addMapper(mapper);
					}
					return service;
				}))
		});
	}
}

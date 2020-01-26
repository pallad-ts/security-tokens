import {Module as _Module, StandardActions} from "@pallad/modules";
import {Container, onActivation} from "alpha-dic";
import {References} from "./References";
import {SecurityTokens} from "@pallad/security-tokens";
import {PREDICATE} from "./securityTokenRuleAnnotation";
import {SecurityTokenRule} from "@pallad/security-tokens/compiled";

export class Module extends _Module<{ container: Container }> {
    init(): void {
        this.registerAction(StandardActions.INITIALIZATION, context => {
            context.container.definitionWithConstructor(References.SECURITY_TOKENS, SecurityTokens)
                .annotate(onActivation(async function (this: Container, service: SecurityTokens) {
                    for (const rule of await this.getByAnnotation<SecurityTokenRule>(PREDICATE)) {
                        service.addRule(rule);
                    }
                    return service;
                }))
        });
    }
}
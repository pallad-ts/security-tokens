import {Annotation, Service} from "alpha-dic";
import {securityTokenRuleAnnotation} from "./securityTokenRuleAnnotation";

export function SecurityTokenRuleService() {
    return function (clazz: { new(...args: any[]): any }) {
        Service()(clazz);
        Annotation(securityTokenRuleAnnotation())(clazz);
    }
}
export function securityTokenRuleAnnotation() {
    return {name: NAME};
}

const NAME = '@pallad/security-tokens/rule';

export const PREDICATE = (x: any) => x && x.name === NAME;
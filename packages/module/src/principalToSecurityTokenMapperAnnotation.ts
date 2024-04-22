import { createAnnotationFactory, Service } from "@pallad/container";

export const principalToSecurityTokenMapperAnnotation = createAnnotationFactory(
	"@pallad/security-tokens-module/principalToSecurityTokenMapper"
);

// eslint-disable-next-line @typescript-eslint/naming-convention
export function PrincipalToSecurityTokenMapperService(): ClassDecorator {
	return target => {
		Service()(target as any);
		principalToSecurityTokenMapperAnnotation.decorator()(target);
	};
}

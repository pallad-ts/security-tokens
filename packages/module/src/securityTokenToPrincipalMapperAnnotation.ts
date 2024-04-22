import { ClassConstructor, createAnnotationFactory, Service } from "@pallad/container";

export const securityTokenToPrincipalMapperAnnotation = createAnnotationFactory(
	"@pallad/security-tokens-module/securityTokenToPrincipalMapper"
);

// eslint-disable-next-line @typescript-eslint/naming-convention
export function SecurityTokenToPrincipalMapperService(): ClassDecorator {
	return target => {
		Service()(target as any);
		securityTokenToPrincipalMapperAnnotation.decorator()(target);
	};
}

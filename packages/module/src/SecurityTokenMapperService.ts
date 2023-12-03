import {Annotation, Service} from "alpha-dic";
import {securityTokenMapperAnnotation} from "./securityTokenMapperAnnotation";

// eslint-disable-next-line @typescript-eslint/naming-convention
export function SecurityTokenMapperService() {
	return function (clazz: { new(...args: any[]): any }) {
		Service()(clazz);
		Annotation(securityTokenMapperAnnotation())(clazz);
	}
}

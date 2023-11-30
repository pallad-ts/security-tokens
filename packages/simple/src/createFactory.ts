import {TokenSimple} from './TokenSimple';


export interface Factory<TType extends string, TValue> {
	(value: TValue): TokenSimple<TType, TValue>;

	is(value: any): value is TokenSimple<TType, TValue>;
}

export function createFactory<TValue = string, TType extends string = string>(type: TType) {
	const func: Factory<TType, TValue> = (value: TValue) => {
		return new TokenSimple(value, type);
	};

	func.is = (value: any): value is TokenSimple<TType, TValue> => {
		return value instanceof TokenSimple && value.type === type;
	};
	return func;
}

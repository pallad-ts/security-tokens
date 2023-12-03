import {Token} from "./Token";

export class TokenSimple<TType extends string = string, TValue = string> extends Token {
	constructor(readonly value: TValue, readonly type: TType) {
		super();
		Object.freeze(this);
	}

	static createFactory<TValue = string, TType extends string = string>(type: TType) {
		const func: TokenSimple.Factory<TType, TValue> = (value: TValue) => {
			return new TokenSimple(value, type);
		};

		func.is = (value: any): value is TokenSimple<TType, TValue> => {
			return value instanceof TokenSimple && value.type === type;
		};
		return func;
	}
}

export namespace TokenSimple {
	export interface Factory<TType extends string, TValue> {
		(value: TValue): TokenSimple<TType, TValue>;

		is(value: any): value is TokenSimple<TType, TValue>;
	}

}

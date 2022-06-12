import {TypeCheck} from "@pallad/type-check";

const TYPE_CHECK = new TypeCheck<Token>('@pallad/security-tokens/Token');

export abstract class Token extends TYPE_CHECK.clazz {
};

export namespace Token {
	export class None extends Token {

	}

	export const NONE = new None();
}

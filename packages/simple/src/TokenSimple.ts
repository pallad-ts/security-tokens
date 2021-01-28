import { Token } from '@pallad/security-tokens';

export class TokenSimple<TType extends string = string, TValue = string> extends Token {
  constructor(readonly value: TValue, readonly type: TType) {
    super();
    Object.freeze(this);
  }
}

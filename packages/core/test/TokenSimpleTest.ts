import { TokenSimple } from "@src/TokenSimple";
import { assert, IsExact } from "conditional-type-checks";

describe("TokenSimple", () => {
	describe("createFactory", () => {
		const factoryA = TokenSimple.createFactory("a");
		const factoryB = TokenSimple.createFactory("b");

		it("creates token with given value and predefined type", () => {
			expect(factoryA("value")).toEqual(new TokenSimple("value", "a"));

			expect(factoryB("value")).toEqual(new TokenSimple("value", "b"));

			assert<IsExact<ReturnType<typeof factoryA>, TokenSimple<"a", string>>>(true);
			assert<IsExact<ReturnType<typeof factoryB>, TokenSimple<"b", string>>>(true);
		});

		it("checks if it is a token from given factory", () => {
			const tokenA = factoryA("value");
			const tokenB = factoryB("value");

			expect(factoryA.is(tokenA)).toBe(true);
			expect(factoryB.is(tokenA)).toBe(false);
			expect(factoryA.is(tokenB)).toBe(false);
			expect(factoryB.is(tokenB)).toBe(true);
		});

		it("types for custom generics", () => {
			const factory = TokenSimple.createFactory<"bla">("a");

			assert<IsExact<Parameters<typeof factory>, ["bla"]>>(true);
		});
	});
});

export class SecurityTokenError extends Error {
	readonly code!: string;

	constructor(message: string) {
		super(message);
		this.name = "SecurityTokenError";
		this.message = message;
	}
}

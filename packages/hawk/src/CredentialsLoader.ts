import { server } from "hawk";

export type CredentialsLoader = (
	id: string
) => Promise<server.Credentials | undefined> | undefined | server.Credentials;

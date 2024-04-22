import { Jwt, JwtPayload } from "jsonwebtoken";

export type JWT<T extends JwtPayload = JwtPayload> = Jwt & { payload: T };

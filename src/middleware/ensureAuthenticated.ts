import { Request, Response, NextFunction } from "express";
import { verify } from 'jsonwebtoken';

interface IPayload {
    sub: string,
}

export function ensureAuthenticated(request: Request, response: Response, next: NextFunction) {
    const authToken = request.headers.authorization;

    if (!authToken) {
        return response.status(401).json({
            errorCode: "token.invalid",
        });
    }

    // Bearer d488040e8982d8cc898129d8960bf31a
    // [0] Bearer
    // [1] d488040e8982d8cc898129d8960bf31a

    const [,token] = authToken.split(" ");

    try {
        const { sub } = verify(token, process.env.JWT_SECRET) as IPayload;

        request.user_id = sub;
        
        return next();

    } catch (err) {
        return response.status(401).json({
            errorCode: "token.expired"
        });
    }

}
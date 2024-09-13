import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { fromZodError } from 'zod-validation-error';

export const errorHandler = (err: Error, req: Request, res: Response, next: NextFunction) => {
    if (err) {
        console.error(err);
        if (err.name === 'CastError') res.status(400).send('error: format ID tidak valid');
        else if (err instanceof ZodError) {
            const error = fromZodError(err);
            res.status(400).send(error.message);
        }
        else res.status(400).send(`error: ${err.message}`);
    }
    next();
}
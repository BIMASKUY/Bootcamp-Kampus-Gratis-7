import express from 'express';
import dotenv from 'dotenv';
import routes from './routes';
import { logger } from './middlewares/logger.middleware';
import { errorHandler } from './middlewares/error.middleware';
import { databaseConnection } from './databases/db.database';

const app = express();

dotenv.config();
databaseConnection();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(logger);
app.use('/', routes);
app.use(errorHandler);

export default app;
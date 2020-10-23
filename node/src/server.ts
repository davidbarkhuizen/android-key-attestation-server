import { default as express } from 'express';
import { Express } from 'express-serve-static-core';

import { router as deviceRouter } from './device.controller';
import { router as rootRouter } from './root.controller';
import { getIpByInterface } from './util';

interface IConfigurationData {
    port: string;
}

const configure = (): IConfigurationData => ({
    port: process.env.FLUID_SERVER_PORT
});

const onServerStarted = (config: IConfigurationData) => {
    const ipsByInterface = getIpByInterface();
    console.log(`indrajala-fluid-server (nodejs) listening @ http://host:${config.port} where host E ${JSON.stringify(ipsByInterface)}`);
};

let app: Express = null;

const launchHttpServer = (config: IConfigurationData) => {

    app = express();

    app.use(express.json());

    app.use('/device', deviceRouter);
    app.get('/', rootRouter);

    app.listen(config.port, () => onServerStarted(config));
};

const go = () => {
    launchHttpServer(configure()); 
};

go();
import { default as express } from 'express';
import { Express } from 'express-serve-static-core';
import { configure, IConfigurationData } from './config';

import { router as deviceRouter } from './controller/device';
import { router as rootRouter } from './controller/root';
import { getIpsForInterfaces } from './util';

// DEBUG
//
require('source-map-support').install();

const onServerStarted = (config: IConfigurationData) => {
    
    console.log(`indrajala-fluid-server (nodejs) listening @ http://host:${config.port} where host E`)
    
    const ipsByInterface = getIpsForInterfaces();
    for (var [interfaceName, hosts] of ipsByInterface) {
        console.log(`interface: ${interfaceName} -> host(s): ${hosts.join(', ')}`);
    }
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
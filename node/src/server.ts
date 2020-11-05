import { default as express } from 'express';
import { Express } from 'express-serve-static-core';
import { configure, IConfigurationData } from './config';

import { router as rootRouter } from './controller/root';
import { logRequest, logResponse } from './middleware/logging';
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

    // TODO this isn't working properly
    app.use(logRequest);

    app.use(rootRouter);

    // TODO this isn't working properly
    app.use(logResponse);

    app.listen(config.port, () => onServerStarted(config));
};

const go = () => {
    launchHttpServer(configure()); 
};

go();
import { default as express } from 'express';
import { Express } from 'express-serve-static-core';
import { configure, IConfigurationData } from './config';

import { rootRouter as rootRouter } from './api/root';
import { logRequest, logResponse } from './middleware/logging';
import { getIpsForInterfaces } from './general/util';

// DEBUG
//
import { default as sourceMapSupport } from 'source-map-support';
sourceMapSupport.install();

const onServerStarted = (config: IConfigurationData) => {
    
    console.log(`fluid-server (C) 2020 Indrajala`);
    console.log(`nodejs ${process.version}`);
    console.log(`http server listening on http://host:${config.port}, where`);
    
    const ipsByInterface = getIpsForInterfaces();
    for (const [interfaceName, hosts] of ipsByInterface) {
        console.log(`for network interface ${interfaceName}, host E {${hosts.join(', ')}}`);
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
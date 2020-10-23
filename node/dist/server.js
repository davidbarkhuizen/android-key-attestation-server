"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const device_controller_1 = require("./device.controller");
const root_controller_1 = require("./root.controller");
const util_1 = require("./util");
require('source-map-support').install();
const configure = () => ({
    port: process.env.FLUID_SERVER_PORT
});
const onServerStarted = (config) => {
    const ipsByInterface = util_1.getIpByInterface();
    console.log(`indrajala-fluid-server (nodejs) listening @ http://host:${config.port} where host E ${JSON.stringify(ipsByInterface)}`);
};
let app = null;
const launchHttpServer = (config) => {
    app = express_1.default();
    app.use(express_1.default.json());
    app.use('/device', device_controller_1.router);
    app.get('/', root_controller_1.router);
    app.listen(config.port, () => onServerStarted(config));
};
const go = () => {
    launchHttpServer(configure());
};
go();
//# sourceMappingURL=server.js.map
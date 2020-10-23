"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getIpByInterface = void 0;
const os_1 = require("os");
exports.getIpByInterface = () => {
    const nets = os_1.networkInterfaces();
    const ipByInterface = {};
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                if (!ipByInterface[name]) {
                    ipByInterface[name] = [];
                }
                ipByInterface[name].push(net.address);
            }
        }
    }
    return ipByInterface;
};
//# sourceMappingURL=util.js.map
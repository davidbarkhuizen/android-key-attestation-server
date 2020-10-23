import { networkInterfaces } from 'os';

export const getIpByInterface = () => {

    const nets = networkInterfaces();

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
}
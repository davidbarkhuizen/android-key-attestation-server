import { networkInterfaces } from 'os';

export const getIpsForInterfaces = (): Map<string,Array<string>> => {

    const nets = networkInterfaces();

    const ipByInterface = new Map<string,Array<string>>();

    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {

            if (net.family === 'IPv4' && !net.internal) {
                if (ipByInterface.get(name) === undefined) {
                    ipByInterface.set(name, [])
                }
    
                ipByInterface.get(name).push(net.address);
            }
        }
    }

    return ipByInterface;
}

export const safeDateFromMS = (ms: number | null): Date | null => {
    if (!ms) {
        return undefined;
    }

    return new Date(ms);
}

export const enumMap = (o: any) => {

    const source = Object.keys(o)
        .filter(key => !isNaN(parseInt(key)))
        .map(key => [parseInt(key), o[key].toString()]) as Array<[number, string]>;

    return new Map<number, string>(source);
}
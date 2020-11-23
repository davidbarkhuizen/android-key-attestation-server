export const logRequest = (req: Express.Request, rsp: Express.Response, next: () => void): void => {

    // if (req.body && req.body != {}) {
    //     console.log('RQ', req.body);
    // }

    next()
};

export const logResponse = (req: Express.Request, rsp: Express.Response, next: () => void): void => {

    // if (rsp.body && rsp.body != {}) {
    //     console.log('RSP', rsp.body);
    // }

    next()
};
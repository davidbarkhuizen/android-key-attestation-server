export const logRequest = (req, rsp, next) => {

    // if (req.body && req.body != {}) {
    //     console.log('RQ', req.body);
    // }

    next()
};

export const logResponse = (req, rsp, next) => {

    // if (rsp.body && rsp.body != {}) {
    //     console.log('RSP', rsp.body);
    // }

    next()
};
import { default as express } from 'express';
import { attestHardwareKey, initiateKeyAttestation } from '../../key_attestation/attestation';
import { IKeyAttInitRq } from './rqrsp/IKeyAttInitRq';
import { IKeyAttInitRsp } from './rqrsp/IKeyAttInitRsp';
import { IKeyAttRq } from './rqrsp/IKeyAttRq';
import { IKeyAttRsp } from './rqrsp/IKeyAttRsp';

export const keyRouter = express.Router();

keyRouter.post('/init', async (req, res) => {

    const rq = req.body as IKeyAttInitRq;

    const result = await initiateKeyAttestation(rq.deviceFingerprint);

    console.log(`request to initiate HW key attestation ${result.succeeded ? 'granted' : 'rejected'}, reference ${result.reference}`);

    res.status(200).json({
        succeeded: result.succeeded,
        reference: result.reference,    
        keyParams: result.keyParams
    } as IKeyAttInitRsp);
});

keyRouter.post('/attest', async (req, res) => {

    const rq = req.body as IKeyAttRq;
    const result = await attestHardwareKey(rq.reference, rq.certChain);

    res.status(200).json({
        reference: result.reference,
        succeeded: result.succeeded
    } as IKeyAttRsp);
});
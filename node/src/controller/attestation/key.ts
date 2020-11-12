import { default as express } from 'express';
import { registerDevice, initiateKeyAttestation } from '../../logic/deviceRegistration';
import { IKeyAttRq } from '../../rqrsp/IKeyAttRq';
import { IKeyAttInitRq } from '../../rqrsp/IKeyAttInitRq';

export const keyRouter = express.Router();

const minDeviceRequirements = {
    apiLevel: 28
};

keyRouter.post('/init', async (req, res) => {

    const rq = req.body as IKeyAttInitRq;

    const permission = await initiateKeyAttestation(
        minDeviceRequirements,
        rq.deviceFingerprint
    );

    res.status(200).json(permission);
});

keyRouter.post('/attest', async (req, res) => {

    const rq = req.body as IKeyAttRq;
    const regResult = await registerDevice(
        minDeviceRequirements,
        rq.registrationID,
        rq.hwAttestationKeyChain
    );

    res.status(200).json(regResult);
});
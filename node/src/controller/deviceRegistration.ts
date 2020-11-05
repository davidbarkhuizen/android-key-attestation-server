import { default as express } from 'express';
import { registerDevice, requestPermissionToRegisterDevice } from '../logic/deviceRegistration';
import { IDeviceRegPermissionRq, IDeviceRegRq } from '../model/rqrsp';

export const router = express.Router();

const minDeviceRequirements = {
    apiLevel: 28
};

router.post('/permission', async (req, res) => {

    const rq = req.body as IDeviceRegPermissionRq;

    const permission = await requestPermissionToRegisterDevice(
        minDeviceRequirements,
        rq.deviceFingerprint
    );

    res.status(200).json(permission);
});

router.post('/register', async (req, res) => {

    const rq = req.body as IDeviceRegRq;
    const regResult = await registerDevice(
        minDeviceRequirements,
        rq.registrationID,
        rq.hwAttestationKeyChain
    );

    res.status(500).json(regResult);
});
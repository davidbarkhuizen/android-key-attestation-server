import { default as express } from 'express';
import { processDeviceRegistration, processIntentToRegisterDevice } from '../../logic/device_registration';
import { IDeviceRegistrationIntent, IDeviceRegistrationPermission, IDeviceRegistrationRq } from '../../model/device';

export const router = express.Router();

let registrationID = 0;

const keySizeBits = 2048;
const keyLifeTimeMinutes = 24 * 60;

router.post('/intent', async (req, res) => {

    const rq = req.body as IDeviceRegistrationIntent;

    const minDeviceRequirements = {
        apiLevel: 28
    };

    const permission = await processIntentToRegisterDevice(rq.deviceFingerprint, minDeviceRequirements);

    res.status(200).json(permission);
});

router.post('/execute', async (req, res) => {

    const rq = req.body as IDeviceRegistrationRq;
    const regResult = await processDeviceRegistration(rq.registrationID, rq.hwAttestationKeyChain);

    res.status(500).json(regResult);
});
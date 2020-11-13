import { IKeyAttestationRecord } from "./model/IKeyAttestationRecord";

const keyAttRecRepo = new Map<string, IKeyAttestationRecord>();

export const setKeyAttRecord = async (rec: IKeyAttestationRecord): Promise<boolean> => {
    keyAttRecRepo.set(rec.id, rec);
    return true;
};

export const getKeyAttRecord = async (id: string): Promise<IKeyAttestationRecord> => {
    return keyAttRecRepo.get(id);
};

export const getKeyAttRecordForReference = async (reference: string): Promise<IKeyAttestationRecord> => {
    
    const values = keyAttRecRepo.values();

    console.log(reference);

    console.log(... values);

    return [... values].find(rec => rec.reference.localeCompare(reference) == 0);
};

// ---------------------------------------------------

const googleKeyAttRootCertsPEMRepo = [];

export const getGoogleKeyAttestationRootCertsPEM = (): Array<string> => {
    return googleKeyAttRootCertsPEMRepo;
};

export const addGoogleKeyAttestationRootCertPEM = (pem: string) => {
    googleKeyAttRootCertsPEMRepo.push(pem);
};

export const removeGoogleKeyAttestationRootCertPEM = (pem: string) => {
    googleKeyAttRootCertsPEMRepo.slice(
        googleKeyAttRootCertsPEMRepo.indexOf(pem)
    );
};
export interface IKeyAttestationRootCert {
    id: string;

    subject: string;
    pem: string;
    expirationDate: string;

    isRevoked: boolean;
    revocationDate: boolean;

    isSuspended: boolean;
    lastSuspensionDate: boolean;
}
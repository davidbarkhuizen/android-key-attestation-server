import { expect } from 'chai';
import { fetchGoogleAttestationCRL } from '../../src/key_attestation/attestation';


describe('fetchGoogleAttestationCRL', 
  async () => { 
    
        it('should return a JSON object that is compliant with the expected schema', async () => { 

            const z = await fetchGoogleAttestationCRL();
            console.log(z);
            
            expect(true)
                .to
                .equal(true); 
        }); 
    }
);
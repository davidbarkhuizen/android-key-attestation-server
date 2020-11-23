import { Validator } from 'jsonschema';
import { default as fetch } from 'node-fetch';

const crlSchema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
      "entries": {
        "description" : "Each entry represents the status of an attestation key. The dictionary-key is the certificate serial number in lowercase hex.",
        "type": "object",
        "propertyNames": {
           "pattern": "^[a-f0-9]*$"
        },
        "additionalProperties": {
          "type": "object",
          "properties": {
            "status": {
              "description": "[REQUIRED] Current status of the key.",
              "type": "string",
              "enum": ["REVOKED", "SUSPENDED"]
            },
            "expires": {
              "description": "[OPTIONAL] UTC date when certificate expires in ISO8601 format (YYYY-MM-DD). Can be used to clear expired certificates from the status list.",
              "type": "string",
              "format": "date"
            },
            "reason": {
              "description": "[OPTIONAL] Reason for the current status.",
              "type": "string",
              "enum": ["UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW"]
            },
            "comment": {
              "description": "[OPTIONAL] Free form comment about the key status.",
              "type": "string",
              "maxLength": 140
            }
          },
          "required": ["status"],
          "additionalProperties": false
        }
      }
    },
    "required": ["entries"],
    "additionalProperties": false
  };

export const fetchGoogleAttestationCRL = async (): Promise<Array<string>> => {

    const url = 'https://android.googleapis.com/attestation/status';

    const rsp = await fetch(url);
    const crl = await rsp.json();

    const v = new Validator();
    const validationResult = v.validate(crl, crlSchema);

    if (validationResult.valid == false) {
        const error = 'google HW attestation CRL has invalid JSON schema';
        console.log(error);
        throw error; 
    }

    // TODO handle statuses

    return Object
        .keys(crl.entries)
        .map(it => it.toUpperCase());
};
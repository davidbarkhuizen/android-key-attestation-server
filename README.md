# indrajala-fluid-server

nodejs typescript server    
demonstrates hardware key attestation  
used in conjunction with indrajala-fluid-client  
  
keywords:  android, kotlin, cryptography, hardware key attestation

## TODO

TEE - SBOX
=> root of trust hash
key params
package
hal keymaster version and whatwhat version
level of attestation

- investigate key usage discrepancies
- refactor recent work on describing with enums
- hw key attestation
  - cert chain validation (key usage and basic constraints is CA)
  - CRL checking
  - move back to dedicated API methods, independent of device registration (for the moment)

- client
  - error handling (esp HTTP failures)

## glossary

token|meaning
-----|-------
PEM|privacy enhanced mail
SO|security officer

## cryptography

### (public key) cert formats

format|description|online parser
------|-----------|-------------
PEM|b64-encoded with begin cert header and end cert trailer|sslshopper.com/certificate-decoder.html
DER|ASN.1 binary|lapo.it/asn1js

### Soft HSM

PKCS#11 compliant software HSM from OpenDNSSec

https://www.opendnssec.org/softhsm/

#### build & install

install build dependencies
```
sudo apt install automake autoconf libtool
```

clone git repo
```
git clone https://github.com/opendnssec/SoftHSMv2.git
```

change current working dir to repo root
```
cd SoftHSMv2
```

execute autogen.sh script
```
SoftHSMv2 $ ./autogen.sh
```

configure the build & installation scripts
```
SoftHSMv2 $./configure
```

compile
```
SoftHSMv2 $ ./make
```

os install
```
SoftHSMv2 $ sudo make install
```

#### configuration

default location of configuration file
```
/etc/softhsm2.conf
```

the location of the config file is itself configurable via environment variable
```
export SOFTHSM2_CONF=/home/user/config.file
```

softhsm2.conf
```
directories.tokendir = /var/lib/softhsm/tokens/
```

#### location of SoftHSM2 pkcs11 module
  
```
SoftHSMv2/src/lib/.libs/libsofthsm2.so
```

### pkcs11-tool

pkcs11-tool is a pkcs#11 compliant CLI client for smartcard-type devices implementing security token functionality, and is packaged as part of open-smartcard (opensc ubuntu apt packaqe)

```
sudo apt install opensc
```

list slots
```
$ pkcs11-tool -L --module ~/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so
Available slots:
Slot 0 (0x0): SoftHSM slot ID 0x0
  token state:   uninitialized
```

initialize slot 0 of token, manually settting SO pin (12345678)
```
$ pkcs11-tool --slot 0 --init-token --label fluid --module ~/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so
ease enter the new SO PIN: 
Please enter the new SO PIN (again): 
Token successfully initialized
```

get basic info on HSM using --show-info
```
$ pkcs11-tool --show-info --module ~/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so
Cryptoki version 2.40
Manufacturer     SoftHSM
Library          Implementation of PKCS11 (ver 2.6)
Using slot 0 with a present token (0x48e10a4b)
```

rescan the module after slot 0 has been initialized
```
 $ pkcs11-tool -L --module ~/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so
Available slots:
Slot 0 (0x48e10a4b): SoftHSM slot ID 0x48e10a4b
  token label        : fluid
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, other flags=0x20
  hardware version   : 2.6
  firmware version   : 2.6
  serial num         : 0daa9668c8e10a4b
  pin min/max        : 4/255
Slot 1 (0x1): SoftHSM slot ID 0x1
  token state:   uninitialized
```

get a list of supported operations by key parameters
```
$ pkcs11-tool --list-mechanisms --slot 0 --module ~/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so
...
RSA-PKCS, keySize={512,16384}, encrypt, decrypt, sign, verify, wrap, unwrap
RSA-PKCS-KEY-PAIR-GEN, keySize={512,16384}, generate_key_pair
RSA-PKCS-OAEP, keySize={512,16384}, encrypt, decrypt, wrap, unwrap
RSA-PKCS-PSS, keySize={512,16384}, sign, verify
RSA-X-509, keySize={512,16384}, encrypt, decrypt, sign, verify
...
SHA512-HMAC, keySize={64,512}, sign, verify
SHA512-RSA-PKCS, keySize={512,16384}, sign, verify
SHA512-RSA-PKCS-PSS, keySize={512,16384}, sign, verify
...
```

create user with PIN
```
$ pkcs11-tool --slot 0x48e10a4b --init-pin --module ~/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so
```


 pkcs11-tool --module ~/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so --login --login-type so --keypairgen --id 1 --key-type RSA:2048




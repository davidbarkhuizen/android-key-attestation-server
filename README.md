# indrajala-fluid-server

fluid server


## cryptography

### (public key) cert formats

PEM
b64-encoded with begin cert header and end cert trailer
parser: https://www.sslshopper.com/certificate-decoder.html

DER
ASN.1 binary
parser: https://lapo.it/asn1js (hex format)

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

#### configure

default location of configuration file
```
/etc/softhsm2.conf
```

the location of the config file is itself configurable via environment variable
```
export SOFTHSM2_CONF=/home/user/config.file
```

#### location of SoftHSM2 pkcs11 module

ubuntu
```
/local/lib/softhsm/libsofthsm2.so
```

### pkcs11-tool

install as part of opensc
```
sudo apt install opensc
```











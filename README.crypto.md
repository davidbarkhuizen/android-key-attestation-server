# Indrajala Reference - Cryptography & Related Tech 

## asn1.1

asn.1 reference card
https://www.oss.com/asn1/resources/reference/asn1-reference-card.html

## format 

pem vs der
https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/#ftoc-heading-10


openssl x509 -inform der -in test.cer -out test.pem


X.690
acronym|asn.1 encoding format|deterministic|length prefix vs EOL marker
-------|---------------------|-------------|---------------------------
BER|basic|N|length prefix
DER|distinguished|Y|length prefix
CER|canonical|Y|EOL marker

### DER


from the [wikipedia entry on X.690](https://en.wikipedia.org/wiki/X.690):

DER encoding:
```
DER (Distinguished Encoding Rules) is a restricted variant of BER for producing unequivocal transfer syntax for data structures described by ASN.1. Like CER, DER encodings are valid BER encodings. DER is the same thing as BER with all but one sender's options removed.

DER is a subset of BER providing for exactly one way to encode an ASN.1 value. DER is intended for situations when a unique encoding is needed, such as in cryptography, and ensures that a data structure that needs to be digitally signed produces a unique serialized representation. DER can be considered a canonical form of BER. For example, in BER a Boolean value of true can be encoded as any of 255 non-zero byte values, while in DER there is one way to encode a boolean value of true.

The most significant DER encoding constraints are:

1. Length encoding must use the definite form
   - Additionally, the shortest possible length encoding must be used
2. Bitstring, octetstring, and restricted character strings must use the primitive encoding
3. Elements of a Set are encoded in sorted order, based on their tag value

DER is widely used for digital certificates such as X.509.
```

BER, CER and DER compared:
```
The key difference between the BER format and the CER or DER formats is the flexibility provided by the Basic Encoding Rules. BER, as explained above, is the basic set of encoding rules given by ITU-T X.690 for the transfer of ASN.1 data structures. It gives senders clear rules for encoding data structures they want to send, but also leaves senders some encoding choices. As stated in the X.690 standard, "Alternative encodings are permitted by the basic encoding rules as a sender's option. Receivers who claim conformance to the basic encoding rules shall support all alternatives".[1]

A receiver must be prepared to accept all legal encodings in order to legitimately claim BER-compliance. By contrast, both CER and DER restrict the available length specifications to a single option. As such, CER and DER are restricted forms of BER and serve to disambiguate the BER standard.

CER and DER differ in the set of restrictions that they place on the sender. The basic difference between CER and DER is that DER uses definitive length form and CER uses indefinite length form in some precisely defined cases. That is, DER always has leading length information, while CER uses end-of-contents octets instead of providing the length of the encoded data. Because of this, CER requires less metadata for large encoded values, while DER does it for small ones.

In order to facilitate a choice between encoding rules, the X.690 standards document provides the following guidance:

The distinguished encoding rules is more suitable than the canonical encoding rules if the encoded value is small enough to fit into the available memory and there is a need to rapidly skip over some nested values. The canonical encoding rules is more suitable than the distinguished encoding rules if there is a need to encode values that are so large that they cannot readily fit into the available memory or it is necessary to encode and transmit a part of a value before the entire value is available. The basic encoding rules is more suitable than the canonical or distinguished encoding rules if the encoding contains a set value or set-of value and there is no need for the restrictions that the canonical and distinguished encoding rules impose.
```


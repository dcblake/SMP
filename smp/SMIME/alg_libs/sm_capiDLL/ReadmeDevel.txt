CAPI Readme

10/17/01
RWC;

############
FINALLY got the verification using DataKey card from Morotola to verify.
Had to use the internal key, with the "AT_KEYEXCHANGE" parameter instead
of the "AT_SIGNATURE" as expected.

	 if(!CryptGetUserKey(this->m_hCryptProv, /*AT_SIGNATURE/*/AT_KEYEXCHANGE, &hRsaKey))

IN ADDITION, it should have worked given the associated certifiate (the one
on the card) public key.  THIS DID NOT WORK; it would appear that the private
key and the internal public key match, but that the internal public key does
not match the key in the certificate.!#$@#$@#%(*&($#*&)(*#&$)(*&^#@$(*&$#!

ALSO, after looking at the KeyUsage bits, I determined that the certificate
restricts access for DigitalSignature ONLY; no encryption.  The other card
must allow encryption.

############
SECOND CARD TEST 
RSA Encryption/Decryption works fine now with default container 
setup.  GREATE NEWS!!!!  MUST USE "wks12C" card for RSA encryption;
the other card ("rsa1024C") is only good for signing.


############
11/6/01
Final test on Sign/Verify using DataKey smartcard AND the certifiate
from the card.  IT IS IMPORTANT TO FIRST TRANSFER the certificate from 
the card to the SYSTEM for the MS Capi CTIL to locate the appropriate
certificate with the correct public key.  The CAPI CTIL was modified to 
look for the actual signer/encrypter public key in each certificate.  
If a certificate with the appropriate public key is not found, an error
occurs.  In these test cards, it was necessary to use the key encryption
private key for signing with the certifiate public key for verifying 
since the cards would not recognize AT_SIGNATURE for private key access.
This worked fine, but will cause problems if both signing and encrypting
keys are present on the card.

Encrypt/Decrypt test worked successfully using the DataKey card and the
certificate from the card.  IMPORTANT::: SEE ABOVE COMMENTS ON 
TRANSFERRING the certificate from the card to the SYSTEM!

DISCOVERED THAT a DataKey ENcrypter card CANNOT verify externally
generated messages, but seems to verify its own generated message(???).
The Default MS Provider(s) can verify RSA messages.

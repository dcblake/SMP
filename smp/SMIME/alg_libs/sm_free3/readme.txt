4/29/04 NOTES for R2.4

Crypto++ 5.1 is now the default.  

All PKCS12 generation logic has been removed from the CTIL.  It has been moved to the CertificateBuilder utility.  The sm_free3 CTIL will still decode/decrypt PKCS12 files, but cannot generate them.

If you need to build with MS Visual Studio .net 2003, the Crypto++ library will have to be patched (see the web site, http://www.eskimo.com/~weidai/cryptlib.html).

- Added exception catch to handle CryptoPP errors and report using the SNACC
exception class for consistency.(Thank you John Stark, sfl mailing list).
- Updated sm_free3 CTIL to handle RSAES_OAEP algorithm.(

10/1/03 NOTES for R2.3

Crypto++ 5.1 has been integrated, to install, perform the following procedures.

load smp/cryptopp51 with the downloaded Crypto++5.1 sources
    http://www.eskimo.com/~weidai/cryptlib.html
copy smp/cryptlib_mod51.dsp to smp/cryptlib_mod.dsp
make clean the cryptlib_mod
make cryptlib_mod
edit smp/SMIME/alg_libs/sm_free3.h
<<<< comment out the CRYPTOPP_5_0, uncomment CRYPTOPP_5_1 >>>>
make clean sm_free3
make sm_free3


Elliptic Curve logic has been added for the sm_free3 CTIL; this includes ECDSA for signature signing and verifying AND ECDH for Key Agreement processing.  This CTIL was also updated to allow the CertificateBuilder utility to build ECDSA and ECDH certificates and PKCS12 files.  It is possible to sign certificates with ECDSA private keys.  One limitation when using the EC private/public keys, is that an ECDSA signer's key cannot be used in the ECDH processing, even though the specifications suggest that the keys can be common.  The EC parameters are very complex and can be specified in several ways.  There are several types of EC curve specifications:  ECP and EC2N, both set by the EC parameters.  For our test utilities, these parameters are specified in a configuration file.


1/31/03 NOTES for R2.2

To use the default "smp/configure" command, place the Crypto++ includes in /usr/local/include/cryptopp and the library in /usr/local/lib.  This convention follows for both 4.2, 5.0 and 5.1.  This will allow the configure command to locate the Crypto++ library and enable the sm_free3 CTIL build automatically.  To change the location of the Crypto++ library and includes, type "configure --help" to determine the commands.

The sm_free3 CTIL is now integrated with Crypto++5.0 by default.  You must remove the define for CRYPTOPP_5_0 from the project settings in order to build Crypto++4.2 and set the appropriate includes and lib in SMPDist (or /usr/local).  In addition, if you wish to sign with 512 bit DSA keys, you must re-build the Crypto++5.0 library with the variable defined "DSA_1024_BIT_MODULUS_ONLY=0".  The default is 1024 bit keys for Crypto++5.0 to be compliant with FIPS.

In order to use Crypto++4.2 on Unix/Linux with GCC 3.2, you must download the patch Crypto++4.2 patch from Wei Dai's web site (below).


PREVIOUS NOTES

Obtain the Crypto++ freeware library from http://www.eskimo.com/~weidai/cryptlib.html.  Our current version is 4.2.  Extract  the library to a subdirectory (e.g. ./util/crypto++4.2 OR the newest
supported version for the SFL).  Be sure to modify the MS DSP project file or Makefile on Unix:

On MS Windows:  Please change the DEBUG C/C++;CodeGeneration settings to reflect the Debug multithreaded DLL (or multithreaded DLL for RELEASE).

On Solaris/Linux:  it is important to remove "-f permissive" from the Makefile CFLAGS parameter (./Makefile).  On my version, the test files fail to compile, simply remove them from the dependency, the library builds and runs fine.

The *.h and *.lib/.a files are moved to ../../SMPDist/Algs/Crypto++4.2 (for example).  This is where the SFL Free3 CTIL expects the source includes and libraries to reside.

The build arguments to the DLL are:

	sm_free3DLL PKCS12_FILE_NAME PASSWORD

For example:

	sm_free3DLL ./certs/DSAFreeGroup1User2X_12.pfx password
	sm_free3DLL							#### FOR VERIFY ONLY

On MS Windows, to make the the test distribution, load the 
smp/SMIME/smimeUtil.dsw workspace.  You can build the "report_tool" and
"testTripleWrap"  projects.  On MS Windows, the 
VDAALLPROJECTS/CertificateBuilder/CertificateBuilder.dsw can also be built.

On Linux, you can make just the "testTripleWrap" program.  The test library
and mimelib is also made, so the MIME library will be available on Linux.
You can make the utility libraries through smp/SMIME/Makefile; "make libsmutil".
You can make testTripleWrap  throug smp/SMIME/testutil/testTripleWrap; "make".
You may have to build the Makefile(s) custom to your environment, this can be
done by uncommenting the "dnl" line in "smp/configure.in" (simply search for
"testutil" to find this line) and running autoconf to re-build the "configure"
script; "autoconf configure.in > configure".  Then, when you re-run the 
"configure" script, the test utility Makefile(s) will be rebuilt using your
custom settings.


- smp/SMIME/smimeUtil.dsw		workspace for test utilities

- smp/SMIME/testutil/testTripleWrap	Sources and test directory for 
sign/encrypt/signin a message and verify/decrypt/verifying a message.

- smp/SMIME/testutil/report_tool	Source to a utility that can handle 
PKCS12 decode/decrypt, SignedData, EnvelopedData and MIME messages and triple 
unwrap MIME or non-MIME messages, dump certificates, etc. (see the usage 
statement when run with no parameters).  This is a good diagnostic tool, but 
I would not suggest attempting to look at this logic as an example due to 
its complex nature.  See smp/SMP_Check or smp/SMIME/testutil/testTripleWrap 
for better demonstration logic.

- VDAALLPROJECTS/CertificateBuilder/CertificateBuilder.dsw	workspace 
for CertificateBuilder

- VDAALLPROJECTS/CertificateBuilder/test.d	Example test directory for 
CertificateBuilder



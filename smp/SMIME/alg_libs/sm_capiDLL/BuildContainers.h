#ifndef BUILDCONTAINERS_H
#define BUILDCONTAINERS_H

#define DK_OK                   0
#define DK_FAIL                 1

#define DK_NOPUBLICKEY          2
#define DK_NOPRIVATEKEYS        3
#define DK_NOCERTIFICATES       4
#define DK_NOTINITIALIZED       5
#define DK_SESSIONHANDLEINVALID 6


extern "C" {
	
	int DK_Initialize();

	int DK_Session(int slot);

	int DK_Login(char *Pin);
		
	int DK_DSAContainers();

	int DK_RSAContainers();

	int DK_AddCertToSystem(char *containername);

	int DK_AddCACertToSystem(char *label);

	int DK_Finalize();
}

#endif
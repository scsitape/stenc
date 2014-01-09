/*
Header file to send and recieve SPIN/SPOUT commands to SCSI device

Original program copyright 2010 John D. Coleman

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#ifndef _SCSIENC_H
#define _SCSIENC_H
#include <string>
#include <bitset>
#include <vector>
#define SSP_KEY_LENGTH          0X20
#define SSP_DESCRIPTOR_LENGTH	1024
#define SSP_PAGE_DES_LENGTH  	24
#define SSP_PAGE_NBES_LENGTH 	16
#define SSP_KAD_HEAD_LENGTH    	4
#define SSP_PAGE_ALLOCATION     8192
#define SSP_UKAD_LENGTH		0x1e

#define KAD_TYPE_UKAD		0x00
#define KAD_TYPE_AKAD		0x01
#define KAD_TYPE_NONCE		0x02
#define KAD_TYPE_META		0x03

#define RDMC_PROTECT		0x03
#define RDMC_UNPROTECT		0x02
#define RDMC_DEFAULT		0x00

//outputs hex in a 2 digit pair
#define HEX( x )    right<<setw(2)<< setfill('0') << hex << (int)( x )<<setfill(' ')
//macro for a byte swapped short
#define BSSHORT( x ) ((unsigned short)( (x[0]<<8) + x[1] ))
//macro for a byte swapped int
#define BSLONG( x )    ((unsigned int)( (int)( x[0] << 24 ) + (int)( x[1] << 16 ) + (int)( x[2] << 8 ) + (int)( x[3] ) ))

#ifdef HAVE_SYS_MACHINE_H
 #include <sys/machine.h>
#endif

#ifdef HAVE_SYS_TYPES_H 
 #include <sys/types.h>
#endif

#ifdef BYTE_ORDER
 #define STENC_BYTE_ORDER BYTE_ORDER
#endif
#ifndef STENC_BYTE_ORDER
 #ifdef __BYTE_ORDER
  #define STENC_BYTE_ORDER __BYTE_ORDER
 #endif
#endif

#ifdef BIG_ENDIAN
 #define STENC_TYPE_BIG_ENDIAN BIG_ENDIAN
#endif
#ifndef STENC_TYPE_BIG_ENDIAN
 #ifdef __BIG_ENDIAN
  #define STENC_TYPE_BIG_ENDIAN __BIG_ENDIAN
 #endif
#endif

#if STENC_BYTE_ORDER == STENC_TYPE_BIG_ENDIAN
 #define STENC_BIG_ENDIAN 1
#else
 #define STENC_BIG_ENDIAN 0
#endif





typedef struct {
    unsigned char pageCode		[2]; 
    unsigned char length		[2];

#if STENC_BIG_ENDIAN == 1
    unsigned char nexusScope 		:3;
    unsigned char res_bits_1		:2;
    unsigned char keyScope		:3;
#else
    unsigned char keyScope		:3;
    unsigned char res_bits_1		:2;
    unsigned char nexusScope 		:3;
#endif
    unsigned char encryptionMode;
    unsigned char decryptionMode;
    unsigned char algorithmIndex;
    unsigned char keyInstance		[4];
#if STENC_BIG_ENDIAN == 1
    unsigned char res_bits_2		:1;
    unsigned char parametersControl	:3;
    unsigned char VCELB			:1;
    unsigned char CEEMS			:2;
    unsigned char RDMD 			:1;
#else
    
    unsigned char RDMD 			:1;
    unsigned char CEEMS			:2;
    unsigned char VCELB			:1;
    unsigned char parametersControl	:3;
    unsigned char res_bits_2		:1;
#endif
    unsigned char res_bits_3;
    unsigned char ASDKCount		[2];
    unsigned char res_bits_4		[8];

} SSP_PAGE_DES; //device encryption status page

typedef struct {
    unsigned char type;
#if STENC_BIG_ENDIAN == 1
    unsigned char res_bits_1 		:5;
    unsigned char authenticated 	:3;
#else
    unsigned char authenticated 	:3;
    unsigned char res_bits_1 		:5;
#endif
    unsigned char descriptorLength	[2];
    unsigned char descriptor		[SSP_DESCRIPTOR_LENGTH]; //will actually be the size of descriptorLength
} SSP_KAD;

typedef struct{
        unsigned char pageCode		[2];
        unsigned char length		[2];
	unsigned char buffer		[SSP_PAGE_ALLOCATION];
} SSP_PAGE_BUFFER; //generic ssp page buffer


typedef struct {
    unsigned char pageCode		[2];
    unsigned char length		[2];
    unsigned char log_obj_num		[8];
#if STENC_BIG_ENDIAN == 1    
    unsigned char compressionStatus 	:4;
    unsigned char encryptionStatus 	:4;
#else
    unsigned char encryptionStatus      :4;
    unsigned char compressionStatus     :4;
#endif
	    
    unsigned char algorithmIndex;
#if STENC_BIG_ENDIAN == 1    
    unsigned char res_bits_1 		:6;
    unsigned char EMES 			:1;
    unsigned char RDMDS 		:1;
#else
    unsigned char RDMDS 		:1;
    unsigned char EMES 			:1;
    unsigned char res_bits_1 		:6;
#endif
    
    unsigned char res_bits_2;
} SSP_PAGE_NBES; //next block encryption status page


typedef struct{
    
#if STENC_BIG_ENDIAN == 0
    unsigned char peripheralQualifier	:3;
    unsigned char periphrealDeviceType	:5;
#else
    unsigned char periphrealDeviceType	:5;
    unsigned char peripheralQualifier	:3;
#endif

#if STENC_BIG_ENDIAN == 0
    unsigned char RMB			:1;
    unsigned char res_bits_1		:7;
#else
    unsigned char res_bits_1		:7;
    unsigned char RMB			:1;
#endif
    unsigned char Version		[1];

#if STENC_BIG_ENDIAN == 0
    unsigned char obs_bits_1		:2;
    unsigned char NORMACA		:1;
    unsigned char HISUP			:1;
    unsigned char responseDataFormat	:4;
#else
    unsigned char responseDataFormat	:4;
    unsigned char HISUP			:1;
    unsigned char NORMACA		:1;
    unsigned char obs_bits_1		:2;
#endif

    unsigned char additionalLength	[1];
    
#if STENC_BIG_ENDIAN == 0
    unsigned char SCCS			:1;
    unsigned char ACC			:1;
    unsigned char TPGS			:2;
    unsigned char threePC		:1;
    unsigned char res_bits_2		:2;
    unsigned char protect		:1;
#else
    unsigned char protect		:1;
    unsigned char res_bits_2		:2;
    unsigned char threePC		:1;
    unsigned char TPGS			:2;
    unsigned char ACC			:1;
    unsigned char SCCS			:1;
#endif


#if STENC_BIG_ENDIAN == 0
    unsigned char obs_bits_2		:1;
    unsigned char ENCSERV		:1;
    unsigned char VS			:1;
    unsigned char MULTIP		:1;
    unsigned char MCHNGR		:1;
    unsigned char obs_bits_3		:2;
    unsigned char ADDR16		:1;
#else
    unsigned char ADDR16		:1;
    unsigned char obs_bits_3		:2;
    unsigned char MCHNGR		:1;
    unsigned char MULTIP		:1;
    unsigned char VS			:1;
    unsigned char ENCSERV		:1;
    unsigned char obs_bits_2		:1;
#endif


#if STENC_BIG_ENDIAN == 0
    unsigned char obs_bits_4		:2;
    unsigned char WBUS16		:1;
    unsigned char SYNC			:1;
    unsigned char obs_bits_5		:2;
    unsigned char CMDQUE		:1;
    unsigned char VS2			:1;
#else
    unsigned char VS2			:1;
    unsigned char CMDQUE		:1;
    unsigned char obs_bits_5		:2;
    unsigned char SYNC			:1;
    unsigned char WBUS16		:1;
    unsigned char obs_bits_4		:2;
#endif

    unsigned char vender		[8];
    unsigned char productID		[16];
    unsigned char productRev		[4];
    unsigned char SN			[7];
    unsigned char venderUnique		[12];

#if STENC_BIG_ENDIAN == 0
    unsigned char res_bits_3		:4;
    unsigned char CLOCKING		:2;
    unsigned char QAS			:1;
    unsigned char IUS			:1;
#else
    unsigned char IUS			:1;
    unsigned char QAS			:1;
    unsigned char CLOCKING		:2;
    unsigned char res_bits_3		:4;
#endif

    unsigned char res_bits_4		[1];
    unsigned char versionDescriptor	[16];
    unsigned char res_bits_5		[22];
    unsigned char copyright		[1];																			
} SCSI_PAGE_INQ; //device inquiry response
typedef struct{
#if STENC_BIG_ENDIAN == 1
	unsigned char valid		:1;
	unsigned char responseCode 	:7;
#else
	unsigned char responseCode 	:7;
	unsigned char valid		:1;
#endif	
	unsigned char res_bits_1;

#if STENC_BIG_ENDIAN == 1
	unsigned char filemark		:1;
	unsigned char EOM		:1;
	unsigned char ILI		:1;
	unsigned char res_bits_2	:1;
	unsigned char senseKey		:4;
#else	
	unsigned char senseKey		:4;
	unsigned char res_bits_2	:1;
	unsigned char ILI		:1;
	unsigned char EOM		:1;
	unsigned char filemark		:1;
#endif	
	unsigned char information	[4];
	unsigned char addSenseLen;
	unsigned char cmdSpecificInfo	[4];
	unsigned char addSenseCode;
	unsigned char addSenseCodeQual;
	unsigned char fieldRepUnitCode;
#if STENC_BIG_ENDIAN == 1
	unsigned char sim		:3; // system information message 
	unsigned char bpv		:1; // bit pointer valid 
	unsigned char resvd2		:2; // reserved 
	unsigned char cd		:1; // control/data 
	unsigned char SKSV		:1;

#else	
	unsigned char SKSV		:1;
	unsigned char cd		:1; // control/data 
	unsigned char resvd2		:2; // reserved 
	unsigned char bpv		:1; // bit pointer valid 
	unsigned char sim		:3; // system information message 
#endif	
        unsigned char field		[2]; // field pointer 
	unsigned char addSenseData	[109];
} SCSI_PAGE_SENSE; //sense data response
class KAD_CLASS{
	public:
		std::vector<SSP_KAD> kads;
	protected:
		void loadKADs(SSP_PAGE_BUFFER* buffer, int start);
};


//class used to parse next block encryption status page
class SSP_NBES: public KAD_CLASS{
	public:
		SSP_PAGE_NBES nbes;
		SSP_NBES(SSP_PAGE_BUFFER* buffer);
};
//class used to parse data encryption status page
class SSP_DES: public KAD_CLASS{
        public:
                SSP_PAGE_DES des;
                SSP_DES(SSP_PAGE_BUFFER* buffer);
};


//enum for SCSIEncryptOptions.cryptMode
enum { CRYPTMODE_OFF, CRYPTMODE_MIXED,CRYPTMODE_ON,CRYPTMODE_RAWREAD};

//used to pass parameters to SCSIWriteEncryptOptions
class SCSIEncryptOptions {
	public:
	    int rdmc;
	    bool CKOD;
	    int cryptMode;
	    unsigned int algorithmIndex;
	    std::string cryptoKey;
	    std::string keyName;
	    SCSIEncryptOptions();
};

//Gets encryption options on the tape drive
SSP_DES* SSPGetDES(std::string tapeDevice);
//Gets the encryption status from the tape volume
SSP_NBES* SSPGetNBES(std::string tapeDevice,bool retry);
//Writes encryption options to the tape drive
bool SCSIWriteEncryptOptions(std::string tapeDevice, SCSIEncryptOptions* eOptions);
//Gets device inquiry
SCSI_PAGE_INQ* SCSIGetInquiry(std::string tapeDevice);
#endif

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
#include <config.h>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#ifdef OS_AIX //AIX
 #define _LINUX_SOURCE_COMPAT
 #include <sys/scsi.h>
 #include <sys/scsi_buf.h>
 #include <sys/tape.h>
 #include <sys/Atape.h>
 #define SCSI_TIMEOUT 5
#else //Linux
 #include <scsi/sg.h>
 #include <scsi/scsi.h>
 #define SCSI_TIMEOUT 5000
 #include <stdlib.h>
 #include <string.h>
 #include <fstream>
#endif
#include <sys/mtio.h>
#include "scsiencrypt.h"

#ifdef HAVE_UNISTD_H
 #include <unistd.h> //added for archlinux support per fukawi2@gmail.com
#endif

#define SSP_SPIN_OPCODE             0XA2
#define SSP_SPOUT_OPCODE            0XB5
#define SSP_SP_CMD_LEN              12
#define SSP_SP_PROTOCOL_TDE         0X20 

#define RETRYCOUNT 1

#define BSINTTOCHAR(x)     (unsigned char)((x & 0xff000000)>>24), (unsigned char)((x & 0x00ff0000)>>16),(unsigned char)((x & 0x0000ff00)>>8),(unsigned char)(x & 0x000000ff)


using namespace std;


void byteswap(unsigned char* array,int size,int value);
bool moveTape(std::string tapeDevice,int count,bool dirForward);
void outputSense(SCSI_PAGE_SENSE* sd);
void readIOError(int err);

bool SCSIExecute(string tapedevice, unsigned char* cmd_p,int cmd_len,unsigned char* dxfer_p,int dxfer_len, bool cmd_to_device, bool show_error);

typedef struct { //structure for setting data encryption
        unsigned char pageCode		[2];
        unsigned char length		[2];
	
#if STENC_BIG_ENDIAN == 1
        unsigned char scope		:3;
        unsigned char res_bits_1	:4; 
        unsigned char lock		:1;
#else
        unsigned char lock              :1;
        unsigned char res_bits_1        :4;
        unsigned char scope             :3;
#endif

#if STENC_BIG_ENDIAN == 1
        unsigned char CEEM		:2;
        unsigned char RDMC		:2;
        unsigned char sdk		:1;
        unsigned char ckod		:1;
        unsigned char ckorp		:1;
        unsigned char ckorl		:1;
#else
	unsigned char ckorl		:1;
        unsigned char ckorp		:1;
        unsigned char ckod		:1;
        unsigned char sdk		:1;
        unsigned char RDMC		:2;
        unsigned char CEEM		:2;
#endif 
        unsigned char encryptionMode;
        unsigned char decryptionMode;
        unsigned char algorithmIndex;
        unsigned char keyFormat;
        unsigned char res_bits_2	[8];
        unsigned char keyLength		[2];
        unsigned char keyData		[SSP_KEY_LENGTH];
} SSP_PAGE_SDE;

unsigned char
	scsi_sense_command[6]={
		0x03,
		0,0,0,
		sizeof(SCSI_PAGE_SENSE),
		0
	},
	scsi_inq_command[6] = {
		0x12,
		0,0,0, 
		sizeof(SCSI_PAGE_INQ), 
		0
	},
        spin_des_command [SSP_SP_CMD_LEN] = {
            	SSP_SPIN_OPCODE,
            	SSP_SP_PROTOCOL_TDE,
            	0,
            	0X20, 
            	0,0, 
            	BSINTTOCHAR(sizeof(SSP_PAGE_BUFFER)),
            	0,0
        },
        spin_nbes_command [SSP_SP_CMD_LEN] = {
            	SSP_SPIN_OPCODE,
            	SSP_SP_PROTOCOL_TDE,
            	0,
            	0X21, 
            	0,0, 
            	BSINTTOCHAR(sizeof(SSP_PAGE_BUFFER)),
            	0,0
        };

//Gets encryption options on the tape drive
SSP_DES* SSPGetDES(string tapeDevice){
        SSP_PAGE_BUFFER buffer;
        memset(&buffer,0,sizeof(SSP_PAGE_BUFFER));
        if(!SCSIExecute(tapeDevice,
                (unsigned char*)&spin_des_command,
                sizeof(spin_des_command),
                (unsigned char*)&buffer,
                sizeof(SSP_PAGE_BUFFER),
                false,true))
        {
		return NULL;
        }
        SSP_DES* status=new SSP_DES(&buffer);
	return status;

}

//Gets encryption options on the tape drive
SSP_NBES* SSPGetNBES(string tapeDevice,bool retry){

	SSP_PAGE_BUFFER  buffer;
        memset(&buffer,0,sizeof(SSP_PAGE_BUFFER));
        if(!SCSIExecute(tapeDevice,
                (unsigned char*)&spin_nbes_command,
                sizeof(spin_nbes_command),
                (unsigned char*)&buffer,
                sizeof(SSP_PAGE_BUFFER),
                false,false))
        {
		return NULL;
        }
	SSP_NBES* status=new SSP_NBES(&buffer);
	if(status->nbes.encryptionStatus==0x01 && retry){ 
		//move to the start of the tape and try again
		int moves=0;
		while(true){
			if(status==NULL)break;
			if(status->nbes.encryptionStatus!=0x01)break;
			if(moves>=MAX_TAPE_READ_BLOCKS)break;
			delete status;
			if(!moveTape(tapeDevice,1,true))break;
			moves++;
			status=SSPGetNBES(tapeDevice,false);
		}
		moveTape(tapeDevice,moves,false);
	}
	return status;



}

//Sends and inquiry to the device
SCSI_PAGE_INQ* SCSIGetInquiry(string tapeDevice){
	SCSI_PAGE_INQ* status=new SCSI_PAGE_INQ;
	memset(status,0,sizeof(SCSI_PAGE_INQ));
	if(!SCSIExecute(tapeDevice,
	                (unsigned char*)&scsi_inq_command,
	                sizeof(scsi_inq_command),
	               (unsigned char*)status,
	                sizeof(SCSI_PAGE_INQ),
	                false,true))
        {
        	exit(EXIT_FAILURE);
        }
	return status;
			  
}


//Writes encryption options to the tape drive
bool SCSIWriteEncryptOptions(string tapeDevice, SCSIEncryptOptions* eOptions){
    	
	char buffer[1024];
	memset(&buffer,0,1024);

	SSP_PAGE_SDE options;
	//copy the template over the options
	memset(&options,0, sizeof(SSP_PAGE_SDE));
	byteswap((unsigned char*)&options.pageCode,2,0x10);
	int pagelen=sizeof(SSP_PAGE_SDE);
	options.scope=2; //all IT nexus = 10b
	options.RDMC=eOptions->rdmc; 
	options.ckod=(eOptions->CKOD)?1:0;
	options.CEEM=DEFAULT_CEEM;
	options.algorithmIndex=eOptions->algorithmIndex;
	//set the specific options
	switch(eOptions->cryptMode){
		case CRYPTMODE_ON: //encrypt, read only encrypted data
			options.encryptionMode=2;
			options.decryptionMode=2;
			break;
		case CRYPTMODE_MIXED: //encrypt, read all data
			options.encryptionMode=2;
			options.decryptionMode=3;
			break;
		case CRYPTMODE_RAWREAD:
			options.encryptionMode=2;
			options.decryptionMode=1;
			break;
		default:
			byteswap((unsigned char*)options.keyLength,2,DEFAULT_KEYSIZE);
			eOptions->cryptoKey=""; //blank the key
			eOptions->keyName=""; //blank the key name, not supported when turned off
			break;
	}
	
	if(eOptions->cryptoKey!=""){
		//byte swap the keylength
		byteswap((unsigned char*)&options.keyLength,2,eOptions->cryptoKey.size());
		//copy the crypto key into the options
		eOptions->cryptoKey.copy((char*)&options.keyData, eOptions->cryptoKey.size(),0);
	}
	//create the key descriptor
	if(eOptions->keyName!=""){
		SSP_KAD kad;
		kad.type=0x00;
		kad.authenticated=0;
		//set the descriptor length to the length of the keyName
		byteswap((unsigned char*)&kad.descriptorLength,2,eOptions->keyName.size());
		
		//get the size of the kad object
		int kadlen=eOptions->keyName.size()+SSP_KAD_HEAD_LENGTH;	
		//increment the SPOUT page len
		pagelen+=kadlen;
		//increase the page size
		eOptions->keyName.copy((char*)&kad.descriptor,eOptions->keyName.size(),0);
		//copy the kad after the SDE command
		memcpy(&buffer[sizeof(SSP_PAGE_SDE)],&kad,kadlen);
	}
	//update the pagelen in options
	byteswap((unsigned char*)&options.length,2,pagelen-4); //set the page length, minus the length and pageCode

	//copy the options to the beginning of the buffer
	memcpy(&buffer,&options,sizeof(SSP_PAGE_SDE));
	
	unsigned char spout_sde_command [SSP_SP_CMD_LEN] = {
                SSP_SPOUT_OPCODE,
                SSP_SP_PROTOCOL_TDE,
                0,
                0X10,
                0,0,
                BSINTTOCHAR(pagelen),
                0,0
        };
	

	//return whether or not the command executed
	return SCSIExecute(
		tapeDevice,
        	(unsigned char*)&spout_sde_command,
        	sizeof(spout_sde_command),
        	(unsigned char*)&buffer,
        	pagelen,
        	true,true
    	);  
}

bool SCSIExecute(string tapedrive, unsigned char* cmd_p,int cmd_len,unsigned char* dxfer_p,int dxfer_len, bool cmd_to_device, bool show_error)
{
	const char* tapedevice=tapedrive.c_str();
	int sg_fd,eresult,sresult,ioerr,retries;
	SCSI_PAGE_SENSE* sd=new SCSI_PAGE_SENSE;
	memset(sd,0,sizeof(SCSI_PAGE_SENSE));
	   
#ifdef OS_AIX //AIX System

	errno=0;
	sg_fd = openx((char*)tapedevice, O_RDONLY , NULL, SC_DIAGNOSTIC);
	if(!sg_fd || sg_fd==-1){
		cerr<<"Could not open device '"<<tapedevice<<"'"<<endl;
		exit(EXIT_FAILURE);
	}

 
	struct sc_iocmd cmdio;
	memset(&cmdio,0,sizeof (struct sc_iocmd));
	//copy the command bytes into the first part of the structure
	memcpy(&cmdio.scsi_cdb,cmd_p,cmd_len);
	cmdio.buffer=(char*)dxfer_p;
	cmdio.timeout_value=SCSI_TIMEOUT;
	cmdio.command_length=cmd_len;
	cmdio.data_length=dxfer_len;
	cmdio.status_validity=SC_SCSI_ERROR;
	cmdio.flags=(cmd_to_device)?B_WRITE:B_READ;

	retries=0;
	do{
		errno=0;
		eresult=ioctl(sg_fd, STIOCMD, &cmdio);
    		sresult=(int)cmdio.scsi_bus_status;
		if(eresult!=0)
			ioerr=errno;
		retries++;
	}while(errno!=0 && retries<=RETRYCOUNT);
	
								       
	if(sresult==SC_CHECK_CONDITION){ //get the sense data
		
		struct sc_iocmd scmdio;
		memset(&scmdio,0,sizeof (struct sc_iocmd));
		//copy the command bytes into the first part of the structure
		memcpy(&scmdio.scsi_cdb,&scsi_sense_command,sizeof(scsi_sense_command));
		scmdio.buffer=(char*)sd;
		scmdio.timeout_value=SCSI_TIMEOUT;
		scmdio.command_length=sizeof(scsi_sense_command);
		scmdio.data_length=sizeof(SCSI_PAGE_SENSE);
		scmdio.status_validity=SC_SCSI_ERROR;
		scmdio.flags=B_READ;

		errno=0;
		ioctl(sg_fd, STIOCMD, &scmdio);

	}

#else //Linux routine
	errno=0;
	sg_fd = open(tapedevice, O_RDONLY);
	if( sg_fd==-1){
		cerr<<"Could not open device '"<<tapedevice<<"': ";
		readIOError(errno);
		exit(EXIT_FAILURE);
	}	
	

	sg_io_hdr_t cmdio;
	memset(&cmdio,0,sizeof(sg_io_hdr_t));
	cmdio.cmd_len = cmd_len;
	cmdio.dxfer_direction =(cmd_to_device)?SG_DXFER_TO_DEV:SG_DXFER_FROM_DEV;
	cmdio.dxfer_len = dxfer_len;
	cmdio.dxferp = dxfer_p;
	cmdio.cmdp = cmd_p;
        cmdio.sbp = (unsigned char*)sd;
        cmdio.mx_sb_len=sizeof(SCSI_PAGE_SENSE);
	cmdio.timeout = SCSI_TIMEOUT; 
	cmdio.interface_id = 'S';
        retries=0;
        do{
                errno=0;
		eresult=ioctl(sg_fd, SG_IO, &cmdio);
                if(eresult!=0)
                        ioerr=errno;
                retries++;
        }while(errno!=0 && retries<=RETRYCOUNT);


	sresult=cmdio.status;
#endif
#ifdef DEBUGSCSI
	cout<<"SCSI Command: ";
	 for(int i=0;i<cmd_len;i++){
		 cout<<HEX(cmd_p[i]);
	 }
	cout<<endl;


	cout<<"SCSI Data: ";
	 for(int i=0;i<dxfer_len;i++){
		 cout<<HEX(dxfer_p[i]);
	 }
	cout<<endl;
#endif
	close(sg_fd);
	

	bool retval=true;	

 	if(eresult!=0){
		if(show_error)
	                readIOError(ioerr);		
		retval=false;

        }

	if(sresult!=0){
 		if(show_error)
                	outputSense(sd);
                retval=false;
	}
	delete sd;
     	return retval;
}
void byteswap(unsigned char* array,int size,int value){
	switch(size){
		case 2:
			array[0]=(unsigned char)((value & 0xff00)>>8);
			array[1]=(unsigned char)(value & 0x00ff);
			break;
		case 4:
			array[0]=(unsigned char)((value & 0xff000000)>>24);
                        array[1]=(unsigned char)((value & 0x00ff0000)>>16);
			array[2]=(unsigned char)((value & 0x0000ff00)>>8);
                        array[3]=(unsigned char)(value & 0x000000ff);

			break;
		default:
			cout<<"Unhandled byte swap length of "<<size<<endl;
			break;
	}
}

	
SCSIEncryptOptions::SCSIEncryptOptions(){
	cryptMode=CRYPTMODE_OFF;
	algorithmIndex=DEFAULT_ALGORITHM;
	cryptoKey="";
	CKOD=false;
	keyName="";
	rdmc=RDMC_DEFAULT;
}

SSP_NBES::SSP_NBES(SSP_PAGE_BUFFER* buffer){
	memset(&nbes,0,sizeof(SSP_PAGE_NBES));
	memcpy(&nbes,buffer,sizeof(SSP_PAGE_NBES));
	loadKADs(buffer,sizeof(SSP_PAGE_NBES));
	
}        
SSP_DES::SSP_DES(SSP_PAGE_BUFFER* buffer){
        memset(&des,0,sizeof(SSP_PAGE_DES));
	memcpy(&des,buffer,sizeof(SSP_PAGE_DES));
	loadKADs(buffer,sizeof(SSP_PAGE_DES));
}

void KAD_CLASS::loadKADs(SSP_PAGE_BUFFER* buffer, int start){
	char* rawbuff=(char*)buffer;
	int length=BSSHORT(buffer->length)+4;
	int pos=start;
        while(pos<length){
                SSP_KAD kad;
                memset(&kad,0,sizeof(SSP_KAD));
                memcpy(&kad,rawbuff+pos,SSP_KAD_HEAD_LENGTH);
                pos+=SSP_KAD_HEAD_LENGTH;
                if(pos>=length)break;
                unsigned short kadDesLen=BSSHORT(kad.descriptorLength);
		if(kadDesLen>0){
        	        memcpy(&kad.descriptor,rawbuff+pos,kadDesLen);
	                pos+=kadDesLen;
		}else pos++;
                kads.push_back(kad);
        }



}
bool moveTape(std::string tapeDevice,int count,bool dirForward){
       struct mtop mt_command;
       int sg_fd = open(tapeDevice.c_str(), O_RDONLY);
       if(!sg_fd || sg_fd==-1){
	       return false;
       }
       errno=0;
       bool retval=true;
#ifdef OS_LINUX
	 
       mt_command.mt_op = (dirForward)?MTFSR:MTBSR;
       mt_command.mt_count = count;
       ioctl(sg_fd, MTIOCTOP, &mt_command);
#else
       mt_command.st_op = (dirForward)?MTFSR:MTBSR;
       mt_command.st_count = count;
       ioctl(sg_fd, STIOCTOP, &mt_command);

#endif
       if(errno!=0)retval=false;
       
       close(sg_fd);
       errno=0;
       return retval;
}

void readIOError(int err){
	if(err==0)return;
	cerr<<"ERROR: ";
        switch(err){
		case EAGAIN:
			cerr<<"Device already open"<<endl;
			break;
                case EBUSY:
                        cerr<<"Device Busy"<<endl;
                        break;
                case ETIMEDOUT:
                        cerr<<"Device operation timed out"<<endl;
                        break;
                case EIO:
			cerr<<"Device I/O Error."<<endl;
			break;						
		case EPERM:
                        cerr<<"You do not have privileges to do this.  Are you root?"<<endl;
                        break;
#ifdef OS_AIX
		case EBADF:
			cerr<<"EBADF"<<endl;
			break;
		case EFAULT:
			cerr<<"EFAULT"<<endl;
			break;
		case EINTR:
			cerr<<"EINTR"<<endl;
			break;
		case EINVAL:
			cerr<<"Invalid device"<<endl;
			break;

		case ENOTTY:
			cerr<<"ENOTTY"<<endl;
			break;

		case ENODEV:
			cerr<<"Device is not responding"<<endl;
			break;

		case ENXIO:
			cerr<<"ENXIO"<<endl;
			break;

#endif
		default:
			if(errno!=0){
				cerr<<"0x"<<hex<<errno<<endl;

			}
	}
	
}
void outputSense(SCSI_PAGE_SENSE* sd){
	cerr<<left<<setw(25)<<"Sense Code: ";

	switch((int)sd->senseKey){
		case 0:
			cerr<<"No specific error";
			break;
		case 2:
			cerr<<"Device not ready";
			break;
		case 3:
			cerr<<"Medium Error";
			break;
		case 4:
			cerr<<"Hardware Error";
			break;
		case 5:
			cerr<<"Illegal Request";
			break;
		case 6:
			cerr<<"Unit Attention";
			break;
		case 7:
			cerr<<"Data protect";
			break;
		case 8:
			cerr<<"Blank tape";
			break;
	
	}
	cerr<<" (0x"<<HEX(sd->senseKey)<<")"<<endl;
	cerr<<left<<setw(25)<<" ASC:"<<"0x"<<HEX(sd->addSenseCode)<<endl;
	cerr<<left<<setw(25)<<" ASCQ:"<<"0x"<<HEX(sd->addSenseCodeQual)<<endl;
	if(sd->addSenseLen>0){
		cerr<<left<<setw(25)<<" Additional data:"<<"0x";
		
		for(int i=0;i<sd->addSenseLen;i++){
			cerr<<HEX(sd->addSenseData[i]);
		}
		cerr<<endl;
	}
#ifdef DEBUGSCSI
	cerr<<left<<setw(25)<<" Raw Sense:"<<"0x";
	char* rawsense=(char*)sd;

        for(int i=0;i<sizeof(SCSI_PAGE_SENSE);i++){
               cerr<<HEX(rawsense[i]);
        }
        cerr<<endl;
#endif
}


/*
stenc - program to set and retrieve hardware based encryption
        options from certain SCSI devices (i.e. LTO4 Tape drives)

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
#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <time.h>
#ifdef OS_LINUX
 #include <stdlib.h>
 #include <string.h>
#endif
#include "scsiencrypt.h"
#include "keyinfo.h"
#define LOGFILE "/var/log/stenc"

typedef struct {
#ifndef SWAPBIT
	unsigned char bit1:1;
	unsigned char bit2:1;
	unsigned char bit3:1;
	unsigned char bit4:1;
	unsigned char bit5:1;
	unsigned char bit6:1;
	unsigned char bit7:1;
	unsigned char bit8:1;
#else
	unsigned char bit8:1;
	unsigned char bit7:1;
	unsigned char bit6:1;
	unsigned char bit5:1;
	unsigned char bit4:1;
	unsigned char bit3:1;
	unsigned char bit2:1;
	unsigned char bit1:1;
#endif
} bitcheck;
using namespace std;
void showUsage();
void errorOut(string message);
void inquiryDrive(string tapeDevice);
void showDriveStatus(string tapeDevice);
void showVolumeStatus(string tapeDevice);
string randomKey(int length);
string timestamp();
void echo(bool);
ofstream logFile;
//program entry point
int main(int argc, char **argv){
    cout<<"stenc v"<<VERSION<<" - SCSI Tape Encryption Manager"<<endl;

    bitcheck bc;
    memset(&bc,0,1);
    bc.bit2=1;
    bc.bit5=1;
    unsigned char check;
    memcpy(&check,&bc,1);

    switch((int)check){
	case 0x12:
		//this is good
		break;
	case 0x48:
#ifndef SWAPBIT
		errorOut("Swapped bit ordering detected.  Program needs to be configured with the --enable-swapbit option in order to function properly on your system");
#else
		errorOut("Swapped bit ordering detected.  Program needs to be configured with the --disable-swapbit option in order to function properly on your system");
#endif
		break;
	default:
		cerr<<"Unknown bit check result "<<HEX(check)<<endl;
		errorOut("Exiting program because it will not run properly");
		break;
    }

    string tapeDrive="";
    bool setting=false;
    string keyFile;
    SCSIEncryptOptions drvOptions;

    	//First load all of the options
    for(int i=1;i<argc;i++){
        string thisCmd=argv[i];
        string nextCmd="";
        if(i+1<argc){
        	if(strncmp(argv[i+1],"-",1)!=0)nextCmd=argv[i+1];
        }
        if(thisCmd=="-g"){ //Check if the help flag was passed.  If it was, show usage and exit
            if(nextCmd=="")errorOut("Key size must be specified when using -g");
            i++; //skip the next argument   
	    int keylength=atoi(nextCmd.c_str());
	    if (keylength % 8 != 0)errorOut("Key size must be divisible by 8");
	    keylength=keylength/8;
            if(keylength>SSP_KEY_LENGTH){
		cout<<"Warning: Keys over "<<(SSP_KEY_LENGTH*8)<<" bits cannot be used by this program!"<<endl;
	    }    
	    string newkey=randomKey(keylength);
	    string keyfilename,keydesc;
	    cout<<"Filename to save key into: ";
	    getline(cin,keyfilename);
            cout<<"Key description (optional): ";
            getline(cin,keydesc);
	    if(keydesc.size()>SSP_UKAD_LENGTH){
		errorOut("Description too long!");
	    }
            ofstream kf;
            kf.open(keyfilename.c_str(),ios::trunc);
            if(!kf.is_open()){
		errorOut("Could not open '"+keyfilename+"' for writing.");

            }
	    kf<<newkey<<keydesc;
	    kf.close();
            cout<<"Random key saved into '"<<keyfilename<<"'"<<endl;
            chmod(keyfilename.c_str(),0600);
            cout<<"Permissions of keyfile set to 600"<<endl;
            exit(EXIT_SUCCESS);
        }
	else if(thisCmd=="-e"){
		if(nextCmd=="")errorOut("Key file not specified after -k option");
		if(nextCmd=="on")drvOptions.cryptMode=CRYPTMODE_ON; //encrypt, read only encrypted data
                else if(nextCmd=="mixed")drvOptions.cryptMode=CRYPTMODE_MIXED;//encrypt, read encrypted and unencrypted data
                else if(nextCmd=="rawread")drvOptions.cryptMode=CRYPTMODE_RAWREAD;//encrypt, read encrypted and unencrypted data
                else if(nextCmd=="off")drvOptions.cryptMode=CRYPTMODE_OFF;//encrypt, read encrypted and unencrypted data
                else errorOut("Unknown encryption mode '"+nextCmd+"'");//encrypt, read encrypted and unencrypted data
		i++; //skip the next argument				
		setting=true;
	}
        else if(thisCmd=="-f"){
            if(nextCmd=="")errorOut("Device not specified after -f option.");
            tapeDrive=nextCmd; //set the tape drive
	    i++; //skip the next argument
        }
	else if(setting){
        	if(thisCmd=="-k"){
	            if(nextCmd=="")errorOut("Key file not specified after -k option");
        	    keyFile=nextCmd; //set the key file
		    i++; //skip the next argument
        	}
		else if(thisCmd=="--protect"){
		    if(drvOptions.rdmc==RDMC_UNPROTECT)errorOut("'--protect' cannot be specified at the same time as '--unprotect'");
		    drvOptions.rdmc=RDMC_PROTECT;
                }
                else if(thisCmd=="--unprotect"){
		    if(drvOptions.rdmc==RDMC_PROTECT)errorOut("'--unprotect' cannot be specified at the same time as '--protect'");
                    drvOptions.rdmc=RDMC_UNPROTECT;
                }
                else if(thisCmd=="--ckod"){
                    drvOptions.CKOD=true;
                }
		else if(thisCmd=="-a"){
        	    if(nextCmd=="")errorOut("You must specify a numeric algorithm index when using the -a flag");
            	    drvOptions.algorithmIndex=atoi(nextCmd.c_str()); 
		    i++; //skip the next argument
		}
		else{
			errorOut("Unknown command '"+thisCmd+"'");
		}
			
        }
	else{
		errorOut("Unknown command '"+thisCmd+"'");
	}

    }

    //validate the tape device
    if(tapeDrive==""){
        errorOut("Tape drive device must be specified with the -f option");
    }
    if(drvOptions.cryptMode==CRYPTMODE_RAWREAD && drvOptions.rdmc==RDMC_PROTECT){
	errorOut("'--protect' is not valid when setting encryption mode to 'rawread'");
    }

#ifndef DISABLE_DEVICE_NAME_CONVERSION
    if(tapeDrive.find(".")==string::npos){
	    if(tapeDrive.substr(0,7)=="/dev/st"){
		tapeDrive="/dev/nst"+tapeDrive.substr(7,tapeDrive.size()-6);
    	}
    
    	if(tapeDrive.substr(0,8)=="/dev/rmt" && tapeDrive.substr(tapeDrive.size()-2,2)!=".1" ){
        	tapeDrive="/dev/rmt"+tapeDrive.substr(8,tapeDrive.size()-7)+".1";
    	}
    }
#endif
    if(getuid()!=0){
	errorOut("You must be root to read or set encryption options on a drive!");
    }
    logFile.open(LOGFILE,ios::app);
    if(!logFile.is_open()){
	cout<<"Warning: Could not open '"<<LOGFILE<<"' for key change auditing!"<<endl;
    }
    chmod(LOGFILE,0600);	
 
    if(!setting){
	cout<<"Status for "<<tapeDrive<<endl;
	cout<<"--------------------------------------------------"<<endl;
	inquiryDrive(tapeDrive);
	showDriveStatus(tapeDrive);
	showVolumeStatus(tapeDrive);
	exit(EXIT_SUCCESS);
    }
   
    Keyinfo ki;
    if(drvOptions.cryptMode!=CRYPTMODE_OFF){
	    if(keyFile==""){
		    string p1="01";
		    string p2="02";
		    string kdesc="";
		    bool done=false;
		    while(!done){
			    cout<<"Enter key in hex format: ";
			    echo(false);
			    getline(cin,p1);
			    echo(true);
			    cout<<endl;
			    cout<<"Re-enter key in hex format: ";
			    echo(false);
			    getline(cin,p2);
			    echo(true);
			    cout<<endl;
			    if(p1!=p2){
				    cout<<"Keys do not match!!"<<endl;
			    }else{
				ki.load(p1);
				if(ki.valid){
					bool descvalid=false;
					while(!descvalid){
						cout<<"Key description (optional): ";
        	                    		getline(cin,kdesc);
						cout<<endl;
						descvalid=true;
						if(kdesc.size()>SSP_UKAD_LENGTH)descvalid=false;
						if(!descvalid)cout<<"Description too long!"<<endl;
					}
					cout<<"Set encryption using this key? [y/n]: ";
					string ans="";
					getline(cin,ans);
					if(ans=="y"){
						done=true;
					}
				}else cout<<"Invalid key!"<<endl;
			    }
		    }
		    drvOptions.keyName=kdesc;
		    
	    }else{
		    //set keyInput here
		    string keyInput,kdesc;
		    ifstream myfile(keyFile.c_str());
		    if (myfile.is_open())
		    {
			  getline (myfile,keyInput);
			  getline (myfile,kdesc);
			  myfile.close();
			  ki.load(keyInput);
			  if(!ki.valid)
				errorOut("Invalid key found in '"+keyFile+"'");
			  if(kdesc.size()>SSP_UKAD_LENGTH)
				errorOut("Key description in '"+keyFile+"' too long!");
			  drvOptions.keyName=kdesc;
		    }else errorOut("Could not open '"+keyFile+"' for reading"); 
			   
	    }
	    drvOptions.cryptoKey.assign(ki.key,ki.keySize);

    }
   
    //Write the options to the tape device
    cout<<"Turning "<<((drvOptions.cryptMode!=CRYPTMODE_OFF)?"on":"off")<<" encryption on device '"<<tapeDrive<<"'..."<<endl;
    bool res=SCSIWriteEncryptOptions(tapeDrive,&drvOptions);
    if(res){

   	SSP_DES* opt=SSPGetDES(tapeDrive);
	if(drvOptions.cryptMode!=CRYPTMODE_OFF && opt->des.encryptionMode!=2){
		errorOut("Turning encryption on for '"+tapeDrive+"' failed!");
	}
        if(drvOptions.cryptMode==CRYPTMODE_OFF && opt->des.encryptionMode!=0){
                errorOut("Turning encryption off for '"+tapeDrive+"' failed!");
        }
	delete opt;

	if(drvOptions.cryptMode!=CRYPTMODE_OFF){
		stringstream msg;
		msg<<"Encryption turned on for device '"<<tapeDrive<<"'. ";
		if(drvOptions.keyName.size()==0)
			msg<<"Key Checksum: "<<ki.check;
		else
			msg<<"Key Descriptor: '"<<drvOptions.keyName<<"'";
	        msg<<" Key Instance: "<<dec<<BSLONG(opt->des.keyInstance)<<endl;

		if(logFile.is_open()){
			logFile<<timestamp()<<": "<<msg.str();
		}
	}else{
		stringstream msg;

		msg<< "Encryption turned off for device '"<<tapeDrive<<"'.";
		msg<<" Key Instance: "<<dec<<BSLONG(opt->des.keyInstance)<<endl;
                
		if(logFile.is_open())
			logFile<<timestamp()<<": "<<msg.str();
	}
	cout<< "Success! See '"<<LOGFILE<<"' for a key change audit log."<<endl;
        exit(EXIT_SUCCESS);
    }
    if(drvOptions.cryptMode!=CRYPTMODE_OFF){
                errorOut("Turning encryption on for '"+tapeDrive+"' failed!");
    }else{
                errorOut("Turning encryption off for '"+tapeDrive+"' failed!");
    }
}
//exits to shell with an error message
void errorOut(string message){
    cerr<<"Error: "<<message<<endl;
    showUsage();
    exit(EXIT_FAILURE);
}

//shows the command usage
void showUsage(){
    cout<<"Usage: stenc -g <length> | -f <device> [-e <on/mixed/rawread/off> [-k <file> ] [-a <number>] [--protect | --unprotect] [--ckod] ]"<<endl;
    cout<<"Type 'man stenc' for more information."<<endl;
}
void inquiryDrive(string tapeDevice){
	SCSI_PAGE_INQ* iresult=SCSIGetInquiry(tapeDevice);
	cout<<left<<setw(25)<<"Device Mfg:";
	cout.write((const char*)iresult->vender,8);
	cout<<endl;
	cout<<left<<setw(25)<<"Product ID:";
	cout.write((const char*)iresult->productID,16);
	cout<<endl;
	cout<<left<<setw(25)<<"Product Revision:";
	cout.write((const char*)iresult->productRev,4);
	cout<<endl;

	delete iresult;
}


void showDriveStatus(string tapeDrive){
        SSP_DES* opt=SSPGetDES(tapeDrive);
	if(opt==NULL)return;
        cout<<left<<setw(25)<<"Data Output:";
	switch ((int)opt->des.decryptionMode){
		case 0x0:
			cout<<"Not decrypting"<<endl;
			cout<<setw(25)<<" "<<"Raw encrypted data not outputted"<<endl;
			break;
                case 0x1:
                        cout<<"Not decrypting"<<endl;
                        cout<<setw(25)<<" "<<"Raw encrypted data outputted"<<endl;
                        break;
		case 0x2:
			cout<<"Decrypting"<<endl;
			cout<<setw(25)<<" "<<"Unencrypted data not outputted"<<endl;
			break;
		case 0x3:
			cout<<"Decrypting"<<endl;
			cout<<setw(25)<<" "<<"Unencrypted data outputted"<<endl;
			break;
		default:
			cout<<"Unknown '0x"<<hex<<(int)opt->des.decryptionMode<<"' "<<endl;
			break;
	}
        cout<<setw(25)<<"Data Input:";
	switch((int)opt->des.encryptionMode){
		case 0x0:
			cout<<"Not encrypting"<<endl;
			break;
		case 0x2:
			cout<<"Encrypting"<<endl;
			break;
		default:
			cout<<"Unknown result '0x"<<hex<<(int)opt->des.encryptionMode<<"'"<<endl;
			break;
	}
	if(opt->des.RDMD==1){
                        cout<<setw(25)<<" "<<"Protecting from raw read"<<endl;
        }


        cout<<setw(25)<<"Key Instance Counter:"<<dec<<BSLONG(opt->des.keyInstance)<<endl;
	if(opt->des.algorithmIndex!=0){
		cout<<setw(25)<<"Encryption Algorithm:"<<hex<<(int)opt->des.algorithmIndex<<endl;
	}
	if(opt->kads.size()>0){
		for(unsigned int i=0;i<opt->kads.size();i++){
			stringstream lbl;
			lbl<<"Drive Key Desc.(";
			switch(opt->kads[i].type){
                                case KAD_TYPE_UKAD:
                                        lbl<<"uKAD): ";
					cout<<setw(25)<<lbl.str();
                        		cout.write((const char*)&opt->kads[i].descriptor,BSSHORT(opt->kads[i].descriptorLength));
                        		cout<<endl;
                                        break;
                                case KAD_TYPE_AKAD:
                                        lbl<<"aKAD): ";
                                        cout<<setw(25)<<lbl.str();
                                        cout.write((const char*)&opt->kads[i].descriptor,BSSHORT(opt->kads[i].descriptorLength));
                                        cout<<endl;
                                        break;
                        }
		}
        }

	delete opt;

}

void showVolumeStatus(string tapeDrive){
        SSP_NBES* opt=SSPGetNBES(tapeDrive,true);
	if(opt==NULL)return;
	if(opt->nbes.compressionStatus!=0){
	        cout<<left<<setw(25)<<"Volume Compressed:";
		switch(opt->nbes.compressionStatus){
			case 0x00:
				cout<<"Drive cannot determine"<<endl;
				break;
			default:
				cout<<"Unknown result '"<<hex<<(int)opt->nbes.compressionStatus<<"'"<<endl;
				break;
		}
	}
        cout<<left<<setw(25)<<"Volume Encryption:";
	switch((int)opt->nbes.encryptionStatus){
		case 0x01:
			cout<<"Unable to determine"<<endl;
			break;
		case 0x02:
			cout<<"Logical block is not a logical block"<<endl;
			break;
		case 0x03:
			cout<<"Not encrypted"<<endl;
			break;
		case 0x05:
			cout<<"Encrypted and able to decrypt"<<endl;
			if(opt->nbes.RDMDS==1)
				cout<<left<<setw(25)<<" "<<"Protected from raw read"<<endl;
			break;
		case 0x06:
			cout<<"Encrypted, but unable to decrypt due to invalid key. "<<endl;
			if(opt->kads.size()>0){
		                for(unsigned int i=0;i<opt->kads.size();i++){
					stringstream lbl;
					lbl<<"Volume Key Desc.(";
					switch(opt->kads[i].type){
						case KAD_TYPE_UKAD:
							lbl<<"uKAD): ";
							cout<<setw(25)<<lbl.str();
							cout.write((const char*)&opt->kads[i].descriptor,BSSHORT(opt->kads[i].descriptorLength));
							cout<<endl;
							break;
						case KAD_TYPE_AKAD:
							lbl<<"aKAD): ";
							cout<<setw(25)<<lbl.str();
							cout.write((const char*)&opt->kads[i].descriptor,BSSHORT(opt->kads[i].descriptorLength));
							cout<<endl;
							break;
					}
                		}
        		}
			if(opt->nbes.RDMDS==1)
				cout<<left<<setw(25)<<" "<<"Protected from raw read"<<endl;
			break;

		default:
			cout<<"Unknown result '"<<hex<<(int)opt->nbes.encryptionStatus<<"'"<<endl;
			break;
	}
	if(opt->nbes.algorithmIndex!=0){
	        cout<<left<<setw(25)<<"Volume Algorithm:"<<(int)opt->nbes.algorithmIndex<<endl;
	}

	delete opt;

}
void echo( bool on = true )
{
  struct termios settings;
  tcgetattr( STDIN_FILENO, &settings );
  settings.c_lflag = on
                   ? (settings.c_lflag |   ECHO )
                   : (settings.c_lflag & ~(ECHO));
  tcsetattr( STDIN_FILENO, TCSANOW, &settings );

}
std::string timestamp(){
        time_t tm;
        time(&tm);
        char buffer[80];
        int len=strftime((char*)&buffer,80,"%Y-%m-%d",localtime(&tm));
        string val;
        val.assign(buffer,len);
        return val;
}

string randomKey(int length)
{
	cout<<"Enter random keys on the keyboard to seed the generator."<<endl<<"End by pressing enter..."<<endl;
	double check=0;
	char c=0;
	echo(false);
	while(c!=10){
		check+=(int)c;
		c=getchar();
	}
	echo(true);
	srand(time(NULL)+(int)check);
	stringstream retval;
	for (int i=0; i<length; i++)
	{
		retval <<HEX(rand() % 256);
	}
	retval << endl;
	return retval.str();
}

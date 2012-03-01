#include <config.h>
#include <iostream>
#include <string.h>
#include <string>
#include <sstream>
#include "keyinfo.h"
#include "scsiencrypt.h"
using namespace std;

Keyinfo::Keyinfo(){
	valid=false;
	check="";
	key=NULL;
	keySize=0;
}
void Keyinfo::load(string hexinput){
	valid=true;
	if(hexinput.size()<2){
		valid=false;
                cout<<"Key input too short!"<<endl;
                return;

	}
	//parse for invalid characters
	for(unsigned int i=0;i<hexinput.size();i++){
		switch((unsigned char)hexinput.at(i)){
			case '0': 
			case '1': 
			case '2': 
			case '3': 
			case '4': 
			case '5': 
			case '6': 
			case '7': 
			case '8':  
			case '9': 
			case 'a': 
			case 'b': 
			case 'c': 
			case 'd': 
			case 'e': 
			case 'f': 
			case 'A': 
			case 'B': 
			case 'C': 
			case 'D': 
			case 'E': 
			case 'F': 
				break;
			default:
				cout<<"Invalid character '"<<hexinput.at(i)<<"' found in key!"<<endl;
				valid=false;
				return;
		}	
	}
	// delete the key if its already allocated
	if(key!=NULL)
		delete key;
	// check that the input size is divisible by 2
	if(hexinput.size()%2!=0){
		valid=false;
		cout<<"Each hexadecimal byte must consist of 2 digits!"<<endl;
		return;
	}
	//convert the hex input to a char*
	loadKey(hexinput);
	//load the check value
	loadCheck();
	//check for oversized key
    	if(keySize==0 || keySize>SSP_KEY_LENGTH){
		cout<<"Key size cannot exceed "<<(SSP_KEY_LENGTH*8)<<" bits!"<<endl;
		cout<<"Provided key is "<<(keySize*8)<<" bits in length."<<endl;
		valid=false;
		return;
    	}	
	cout<<"Provided key length is "<<(keySize*8)<<" bits."<<endl;
	cout<<"Key checksum is "<<check<<"."<<endl;


}
void Keyinfo::loadCheck() {   
	int i;   
	int chk = 0;    
	for (i = 0; i<keySize;i++) {     
		chk += ((int)key[i]) * (i + 1);   
	}
	stringstream retval;
	retval<<hex<<chk;    
	check=retval.str();
}
Keyinfo::~Keyinfo(){
	delete key;
}
void Keyinfo::loadKey(string str)
{
	int length = str.size();
	// make sure the input string has an even digit numbers
	if(length%2 == 1)
	{
		str = "0" + str;
		length++;
	}

	// allocate memory for the output array
	key = new char[length/2];
	memset(key,0,(length/2)+1);
	keySize = length/2;

	stringstream sstr(str);
	for(int i=0; i < keySize; i++)
	{
		char ch1, ch2;
		sstr >> ch1 >> ch2;
		int dig1=0, dig2=0;
		if(isdigit(ch1)) dig1 = ch1 - '0';
		else if(ch1>='A' && ch1<='F') dig1 = ch1 - 'A' + 10;
		else if(ch1>='a' && ch1<='f') dig1 = ch1 - 'a' + 10;
		if(isdigit(ch2)) dig2 = ch2 - '0';
		else if(ch2>='A' && ch2<='F') dig2 = ch2 - 'A' + 10;
		else if(ch2>='a' && ch2<='f') dig2 = ch2 - 'a' + 10;
		key[i] = dig1*16 + dig2;
	}
}

#ifndef KEYINFO_H
#define KEYINFO_H
#include <string>

class Keyinfo{
	public:
		char* key;
	        int keySize;
		bool valid;
		std::string check;
		void load(std::string hexinput);
		Keyinfo();
		~Keyinfo();
	private:
		void loadKey(std::string str);
		void loadCheck();
	
};

#endif

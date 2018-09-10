#pragma once

#include <openssl/pkcs12.h>

using namespace std;

class NativeSessionlessSelector {
public:
	static NativeSessionlessSelector* createNativeSessionlessSelector();
	NativeSessionlessSelector() = default;
	string getCertificate();
	string sign(string message);
private:
	void getFile(X509** cert, EVP_PKEY** key);
	bool rsaSign(RSA* rsa, const unsigned char* msg, size_t msgLen, unsigned char** encMsg, size_t* msgLenEnc);
	void base64Encode(const unsigned char* buffer, size_t length, char** base64Text);
	void storeConfiguration(string fileName, string filePath, string password);
	map<string, string> loadConfigurationFile(string fileName);
	string getFullPath(string fileName);
};
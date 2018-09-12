#pragma once

#include <openssl/pkcs12.h>

using namespace std;

class NativeSessionlessSelector {
public:
	static NativeSessionlessSelector* createNativeSessionlessSelector();
	NativeSessionlessSelector() = default;
	string getCertificate();
	string sign(unsigned char* message, size_t size);
private:
	void getFile(X509** cert, EVP_PKEY** key);
	string rsaSign(RSA* rsa, unsigned char* msg, size_t msgLen);
	void base64Encode(const unsigned char* buffer, size_t length, char** base64Text);
	void storeConfiguration(string fileName, string filePath, string password);
	map<string, string> loadConfigurationFile(string fileName);
	string getFullPath(string fileName);
};
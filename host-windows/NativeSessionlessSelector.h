#pragma once

#include <openssl/pkcs12.h>

using namespace std;

class NativeSessionlessSelector {
public:
	NativeSessionlessSelector() = default;
	string getCertificate();
	string sign(string message);
private:
	void getFile(X509** cert, EVP_PKEY** key);
	bool rsaSign(RSA* rsa, const unsigned char* msg, size_t msgLen, unsigned char** encMsg, size_t* msgLenEnc);
	void base64Encode(const unsigned char* buffer, size_t length, char** base64Text);
};
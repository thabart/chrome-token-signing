#include "NativeSessionlessSelector.h"

#include "BinaryUtils.h"

#include "SessionLessDialog.h"

#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <fstream>

using namespace std;

NativeSessionlessSelector* NativeSessionlessSelector::createNativeSessionlessSelector()
{
	return new NativeSessionlessSelector();
}

string NativeSessionlessSelector::getCertificate() {
	X509* cert = NULL;
	string hex;
	EVP_PKEY* pkey = NULL;
	getFile(&cert, &pkey);
	if (cert == NULL || pkey == NULL) {
		return hex;
	}
	
	unsigned char* buf;
	buf = NULL;
	int len = i2d_X509(cert, &buf);
	// string certificateName = cert->name;
	// ASN1_BIT_STRING* publicKey = cert->cert_info->key->public_key;
	// unsigned char* publicKeyData = publicKey->data;
	hex = BinaryUtils::bin2hex(buf, len);
	return hex;
}

string NativeSessionlessSelector::sign(unsigned char* message, size_t size) {
	X509* cert = NULL;
	EVP_PKEY* pkey = NULL;
	RSA *rsakey;
	string hex;
	getFile(&cert, &pkey);
	if (cert == NULL || pkey == NULL) {
		return hex;
	}

	rsakey = EVP_PKEY_get1_RSA(pkey);
	size_t encMessageLength;
	hex = rsaSign(rsakey, message, size);
	return hex;
}

void NativeSessionlessSelector::getFile(X509** cert, EVP_PKEY** pkey) {
	string fileName = "settings.txt";
	string fullPath = getFullPath(fileName);
	ifstream input(fullPath);
	if (!input.good()) {
		SessionLessDialog sessionLessDialog = SessionLessDialog::getSessionlessCertificate();
		if (sessionLessDialog.password.empty() || sessionLessDialog.certificatePath.empty()) {
			return;
		}

		storeConfiguration(fileName, sessionLessDialog.certificatePath, sessionLessDialog.password);
	}

	map<string, string>  configuration = loadConfigurationFile(fileName);
	string filePath = configuration["file"];
	string password = configuration["password"];
	FILE *fp;
	PKCS12 *p12;
	STACK_OF(X509) *ca = NULL;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	fp = fopen(filePath.c_str(), "rb");
	if (!fp) {
		return;
	}

	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12) {
		return;
	}
	
	PKCS12_parse(p12, password.c_str(), pkey, cert, &ca);
}

map<string, string> NativeSessionlessSelector::loadConfigurationFile(string fileName) {
	string fullPath = getFullPath(fileName);
	ifstream input(fullPath);
	map<std::string, std::string> ans;
	while (input)
	{
		string key;
		string value;
		getline(input, key, ':');
		getline(input, value, '\n');
		string::size_type pos1 = value.find_first_of("\"");
		string::size_type pos2 = value.find_last_of("\"");
		if (pos1 != std::string::npos && pos2 != std::string::npos && pos2 > pos1)
		{
			value = value.substr(pos1 + 1, pos2 - pos1 - 1);
			ans[key] = value;
		}
	}

	input.close();
	return ans;
}

void NativeSessionlessSelector::storeConfiguration(string fileName, string filePath, string password) {
	string fullPath = getFullPath(fileName);
	remove(fullPath.c_str());
	ofstream o(fullPath);
	o << "file:\"" << filePath << "\";" << endl;
	o << "password:\"" << password << "\";" << endl;
	o.close();
}

string NativeSessionlessSelector::getFullPath(string fileName) {
	char path[MAX_PATH];
	HMODULE hModule = GetModuleHandle(NULL);
	GetModuleFileNameA(hModule, path, (sizeof(path)));
	PathRemoveFileSpecA(path);
	return string(path) + "\\" + fileName;
}

string NativeSessionlessSelector::rsaSign(RSA* rsa, unsigned char* msg, size_t msgLen) {

	unsigned char* sigret = (unsigned char*)malloc(256);
	size_t siglen;
	if (RSA_sign(NID_sha1, msg, msgLen, sigret, &siglen, rsa) != 1) {
		return false;
	}

	return BinaryUtils::bin2hex(sigret, siglen);
}

void NativeSessionlessSelector::base64Encode(const unsigned char* buffer, size_t length, char** base64Text) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
	*base64Text = (*bufferPtr).data;
}
#include "NativeSessionlessSelector.h"

#include "BinaryUtils.h"

#include <openssl/pkcs12.h>
#include <openssl/err.h>

using namespace std;

string NativeSessionlessSelector::getCertificate() {
	X509* cert = NULL;
	EVP_PKEY* pkey = NULL;
	getFile(&cert, &pkey);
	if (cert == NULL || pkey == NULL) {
		return NULL;
	}
	
	string certificateName = cert->name;
	ASN1_BIT_STRING* publicKey = cert->cert_info->key->public_key;
	unsigned char* publicKeyData = publicKey->data;
	string hex = BinaryUtils::bin2hex(publicKeyData, publicKey->length);
	return hex;
}

string NativeSessionlessSelector::sign(string message) {
	X509* cert = NULL;
	EVP_PKEY* pkey = NULL;
	RSA *rsakey;
	getFile(&cert, &pkey);
	if (cert == NULL || pkey == NULL) {
		return NULL;
	}

	rsakey = EVP_PKEY_get1_RSA(pkey);
	unsigned char* encMessage;
	char* base64Text;
	size_t encMessageLength;
	rsaSign(rsakey, (unsigned char*)message.c_str(), message.length(), &encMessage, &encMessageLength);
	base64Encode(encMessage, encMessageLength, &base64Text);
	free(encMessage);
	return base64Text;
}

void NativeSessionlessSelector::getFile(X509** cert, EVP_PKEY** pkey) {
	// TODO : EXTERNALIZE THOSE DEPENDENCIES
	char* filePath = "d:\\Projects\\medikit\\chrome-token-signing\\certificates\\certificate.p12";
	char* password = "password";

	FILE *fp;
	PKCS12 *p12;
	STACK_OF(X509) *ca = NULL;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	fp = fopen(filePath, "rb");
	if (!fp) {
		return;
	}

	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12) {
		return;
	}
	
	PKCS12_parse(p12, password, pkey, cert, &ca);
}

bool NativeSessionlessSelector::rsaSign(RSA* rsa, const unsigned char* msg, size_t msgLen, unsigned char** encMsg, size_t* msgLenEnc) {

	EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
	EVP_PKEY* priKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(priKey, rsa);
	if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
		return false;
	}

	if (EVP_DigestSignUpdate(m_RSASignCtx, msg, msgLen) <= 0) {
		return false;
	}

	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, msgLenEnc) <= 0) {
		return false;
	}

	*encMsg = (unsigned char*)malloc(*msgLenEnc);
	if (EVP_DigestSignFinal(m_RSASignCtx, *encMsg, msgLenEnc) <= 0) {
		return false;
	}

	EVP_MD_CTX_cleanup(m_RSASignCtx);
	return true;
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
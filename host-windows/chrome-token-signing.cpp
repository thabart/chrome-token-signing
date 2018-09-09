/*
 * Chrome Token Signing Native Host
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "BinaryUtils.h"
#include "CertificateSelector.h"
#include "Exceptions.h"
#include "jsonxx.h"
#include "Labels.h"
#include "Logger.h"
#include "Signer.h"
#include "VersionInfo.h"

#include <fcntl.h>
#include <io.h>
#include <memory>

#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include "SessionLessDialog.h"

using namespace std;
using namespace jsonxx;

const string DEFAULT_SOURCE = "eid";
const string SESSIONLESS = "sessionless";

string readMessage()
{
	uint32_t messageLength = 0;
	cin.read((char*)&messageLength, sizeof(messageLength));
	if (messageLength > 1024 * 8)
		throw InvalidArgumentException("Invalid message length " + to_string(messageLength));
	string message(messageLength, 0);
	cin.read(&message[0], messageLength);
	_log("Request(%i): %s ", messageLength, message.c_str());
	return message;
}

void sendMessage(const string &message)
{
	uint32_t messageLength = message.length();
	cout.write((char *)&messageLength, sizeof(messageLength));
	_log("Response(%i) %s ", messageLength, message.c_str());
	cout << message;
}

string getPublicCertificate() {
	FILE *fp;
	char* filePath = "c:\\Projects\\medikit\\chrome-token-signing\\certificates\\certificate.p12";
	char* password = "password";
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	fp = fopen(filePath, "rb");
	if (!fp) {
		return NULL;
	}
	
	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12) {
		return NULL;
	}
	
	if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
		return NULL;
	}

	PKCS12_free(p12);

	string certificateName = cert->name;
	ASN1_BIT_STRING* publicKey = cert->cert_info->key->public_key;
	unsigned char* publicKeyData = publicKey->data;
	string hex = BinaryUtils::bin2hex(publicKeyData, publicKey->length);
	return hex;
}

int main(int argc, char **argv)
{
	//Necessary for sending correct message length to stout (in Windows)
	// DialogBoxParam(NULL, MAKEINTRESOURCE(IDD_SESSIONLESS_DIALOG), pParent, DlgProc, )
	
	// SessionLessDialog::getSessionlessCertificate();

	string publickey = getPublicCertificate();
	string s = "";

	/*
	_setmode(_fileno(stdin), O_BINARY);
	_setmode(_fileno(stdout), O_BINARY);
	vector<unsigned char> selectedCert;
	while (true)
	{
		_log("Parsing input...");
		jsonxx::Object jsonRequest, jsonResponse;
		try {
			if (!jsonRequest.parse(readMessage()))
				throw InvalidArgumentException();

			if (!jsonRequest.has<string>("type") || !jsonRequest.has<string>("nonce") || !jsonRequest.has<string>("origin"))
				throw InvalidArgumentException();

			string source = DEFAULT_SOURCE;
			if (jsonRequest.has<string>("source")) {
				source = jsonRequest.get<string>("source");
				if (source != DEFAULT_SOURCE && source != SESSIONLESS) {
					source = DEFAULT_SOURCE;
				}
			}

			static const string origin = jsonRequest.get<string>("origin");
			if (jsonRequest.get<string>("origin") != origin)
				throw InconsistentOriginException();

			if (jsonRequest.has<string>("lang"))
				Labels::l10n.setLanguage(jsonRequest.get<string>("lang"));

			string type = jsonRequest.get<string>("type");
			if (type == "VERSION")
				jsonResponse << "version" << VERSION;
			else if (jsonRequest.get<string>("origin").compare(0, 6, "https:"))
				throw NotAllowedException("Origin doesn't contain https");
			else if (type == "CERT")
			{
				if (source == DEFAULT_SOURCE) {
					unique_ptr<CertificateSelector> certificateSelector(CertificateSelector::createCertificateSelector());
					selectedCert = certificateSelector->getCert(!jsonRequest.has<string>("filter") || jsonRequest.get<string>("filter") != "AUTH");
					jsonResponse << "cert" << BinaryUtils::bin2hex(selectedCert);
				}
				else {

				}
			}
			else if (type == "SIGN")
			{
				if (!jsonRequest.has<string>("cert") || !jsonRequest.has<string>("hash"))
					throw InvalidArgumentException();

				vector<unsigned char> cert = BinaryUtils::hex2bin(jsonRequest.get<string>("cert"));
				vector<unsigned char> digest = BinaryUtils::hex2bin(jsonRequest.get<string>("hash"));
				_log("signing hash: %s, with certId: %s", jsonRequest.get<string>("hash").c_str(), jsonRequest.get<string>("cert").c_str());
				if (cert != selectedCert)
					throw NotSelectedCertificateException();

				unique_ptr<Signer> signer(Signer::createSigner(cert));
				if (!signer->showInfo(jsonRequest.get<string>("info", string())))
					throw UserCancelledException();

				jsonResponse << "signature" << BinaryUtils::bin2hex(signer->sign(digest));
			}
			else
				throw InvalidArgumentException();
		}
		// Only catch terminating exceptions here
		catch (const InvalidArgumentException &e)
		{
			_log("Handling exception: %s", e.getErrorCode());
			sendMessage((Object() << "result" << e.getErrorCode() << "message" << e.what()).json());
			return EXIT_FAILURE;
		}
		catch (const BaseException &e) {
			jsonResponse << "result" << e.getErrorCode() << "message" << e.what();
		}

		if (jsonRequest.has<string>("nonce"))
			jsonResponse << "nonce" << jsonRequest.get<string>("nonce");
		if (!jsonResponse.has<string>("result"))
			jsonResponse << "result" << "ok";
		jsonResponse << "api" << API;
		sendMessage(jsonResponse.json());
	}
	*/
	return EXIT_SUCCESS;
}

#include "SessionLessDialog.h"

#include "Labels.h"
#include "SessionlessDialogResource.h"

#include <iostream>
#include <windows.h>
#include <commdlg.h>
#include <atlstr.h>
#include <fstream>

#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/applink.c>

SessionLessDialog SessionLessDialog::getSessionlessCertificate(HWND pParent)
{
	SessionLessDialog p;
	DialogBoxParam(NULL, MAKEINTRESOURCE(IDD_SESSIONLESS_DIALOG), pParent, DlgProc, LPARAM(&p));
	return p;
}

INT_PTR CALLBACK SessionLessDialog::DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	TCHAR buffer[MAX_PATH] = TEXT("");
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
		// SetDlgItemText(hwndDlg, IDC_MESSAGE, self->message.c_str());
		// SetDlgItemText(hwndDlg, IDC_LABEL, self->label.c_str());
		SetDlgItemText(hwndDlg, IDCANCEL, Labels::l10n.get("cancel").c_str());
		return TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BROWSE_BUTTON:
			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lpstrFilter = L"Certificate Files\0*.p12";
			ofn.lpstrFile = buffer;
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hwndDlg;
			ofn.nMaxFile = MAX_PATH;
			ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;
			if (GetOpenFileName(&ofn)) {

				SetDlgItemText(hwndDlg, IDC_CERTIFICATE_EDIT, ofn.lpstrFile);
			}

			break;
		case IDOK:
		{
			size_t passwordLen = size_t(SendDlgItemMessage(hwndDlg, IDC_PASSWORD_EDIT, EM_LINELENGTH, 0, 0));
			size_t certificateLen = size_t(SendDlgItemMessage(hwndDlg, IDC_CERTIFICATE_EDIT, EM_LINELENGTH, 0, 0));
			std::wstring password(passwordLen + 1, 0);
			std::wstring certificate(certificateLen + 1, 0);
			GetDlgItemText(hwndDlg, IDC_PASSWORD_EDIT, &password[0], password.size());
			GetDlgItemText(hwndDlg, IDC_CERTIFICATE_EDIT, &certificate[0], certificate.size());
			std::string certificateStr = ws2s(certificate);
			std::string passwordStr = ws2s(password);
			if (!checkCertificate(certificateStr, passwordStr)) {
				MessageBox(hwndDlg, L"password is not correct", L"error", MB_OK);
				return FALSE;
			}

			// self->certificatePath = &certificateStr;
			SessionLessDialog *self = (SessionLessDialog*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
			self->password = std::string(passwordStr.cbegin(), passwordStr.cend());
			self->certificatePath = std::string(certificateStr.cbegin(), certificateStr.cend());
			return EndDialog(hwndDlg, IDOK);
		}
		case IDCANCEL:
			return EndDialog(hwndDlg, IDCANCEL);
		}
		return FALSE;
	}
	return FALSE;
}

const std::string SessionLessDialog::ws2s(const std::wstring& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, 0, 0, 0, 0);
	std::string r(len, '\0');
	WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, &r[0], len, 0, 0);
	return r;
}

bool SessionLessDialog::checkCertificate(std::string fullPath, std::string password) {
	FILE *fp;
	PKCS12 *p12;
	X509* cert = NULL;
	EVP_PKEY* pkey = NULL;
	RSA *rsakey;
	STACK_OF(X509) *ca = NULL;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	fp = fopen(fullPath.c_str(), "rb");
	if (!fp) {
		return false;
	}
	
	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12) {
		return false;
	}

	return PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca);
}
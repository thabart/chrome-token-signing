#pragma once

#include "stdafx.h"
#include <string>

class SessionLessDialog
{
public:
	static SessionLessDialog getSessionlessCertificate(HWND pParent = NULL);
	std::string password;
	std::string certificatePath;
private:
	SessionLessDialog() {}
	static INT_PTR CALLBACK DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static bool checkCertificate(std::string fullPath, std::string password);
	static const std::string ws2s(const std::wstring& s);
};
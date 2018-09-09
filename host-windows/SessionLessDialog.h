#pragma once

#include "stdafx.h"
#include <string>

class SessionLessDialog
{
public:
	static std::string getSessionlessCertificate(HWND pParent = NULL);

private:
	SessionLessDialog() {}
	static INT_PTR CALLBACK DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
};
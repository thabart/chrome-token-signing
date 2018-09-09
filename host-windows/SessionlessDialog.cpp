#include "SessionLessDialog.h"

#include "Labels.h"
#include "SessionlessDialogResource.h"

std::string SessionLessDialog::getSessionlessCertificate(HWND pParent)
{
	SessionLessDialog p;
	DialogBoxParam(NULL, MAKEINTRESOURCE(IDD_SESSIONLESS_DIALOG), pParent, DlgProc, LPARAM(&p));
	return "";
}

INT_PTR CALLBACK SessionLessDialog::DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		SessionLessDialog *self = (SessionLessDialog*)lParam;
		SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
		// SetDlgItemText(hwndDlg, IDC_MESSAGE, self->message.c_str());
		// SetDlgItemText(hwndDlg, IDC_LABEL, self->label.c_str());
		SetDlgItemText(hwndDlg, IDCANCEL, Labels::l10n.get("cancel").c_str());
		return TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
		{
			// size_t len = size_t(SendDlgItemMessage(hwndDlg, IDC_PIN_FIELD, EM_LINELENGTH, 0, 0));
			// std::wstring tmp(len + 1, 0);
			// GetDlgItemText(hwndDlg, IDC_PIN_FIELD, &tmp[0], tmp.size());
			// SessionLessDialog *self = (SessionLessDialog*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
			// self->pin = std::string(tmp.cbegin(), tmp.cend());
			return EndDialog(hwndDlg, IDOK);
		}
		case IDCANCEL:
			return EndDialog(hwndDlg, IDCANCEL);
		}
		return FALSE;
	}
	return FALSE;
}


// PEfile_GUI_tools.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'pch.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CPEfileGUItoolsApp:
// See PEfile_GUI_tools.cpp for the implementation of this class
//

class CPEfileGUItoolsApp : public CWinApp
{
public:
	CPEfileGUItoolsApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CPEfileGUItoolsApp theApp;

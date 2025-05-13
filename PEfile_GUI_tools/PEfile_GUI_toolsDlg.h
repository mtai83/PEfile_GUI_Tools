
// PEfile_GUI_toolsDlg.h : header file
//

#pragma once

#include <vector>

struct ImportEntry {
	CString dllName;
	std::vector<CString> functions;
};

// CPEfileGUItoolsDlg dialog
class CPEfileGUItoolsDlg : public CDialogEx
{
// Construction
public:
	CPEfileGUItoolsDlg(CWnd* pParent = nullptr);	// standard constructor


// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PEFILE_GUI_TOOLS_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnTvnSelchangedTreePefile(NMHDR* pNMHDR, LRESULT* pResult);
	CTreeCtrl m_TreeCtrl;
	afx_msg void OnBnClickedBtnSelectFile();
	CButton BTN_SELECT_FILE;
	CEdit m_editFilePath;
	afx_msg bool ReadPEheader(FILE* file, IMAGE_FILE_HEADER& fileHeader, DWORD& peSignature);
	afx_msg bool ReadOptionalHeader(FILE* file, IMAGE_FILE_HEADER& fileHeader, DWORD& peSignature);
	afx_msg bool ReadDataDirecoty(FILE* file, IMAGE_FILE_HEADER& fileHeader, DWORD& peSignature);
	afx_msg bool ReadSectionTable(FILE* file, IMAGE_FILE_HEADER& fileHeader, DWORD& peSignature);
	afx_msg void ReadImportDirectory(FILE* file);
	
private:
	CListCtrl m_listInfo;
	
public:
	CListCtrl m_listDLL;
	std::vector<ImportEntry> m_imports;
	afx_msg void OnLvnItemchangedListInfo(NMHDR* pNMHDR, LRESULT* pResult);
};


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
	IMAGE_DOS_HEADER      m_dosHeader{};
	IMAGE_FILE_HEADER     m_fileHeader{};
	IMAGE_OPTIONAL_HEADER32 m_opt32{};
	IMAGE_OPTIONAL_HEADER64 m_opt64{};
	bool                  m_isPE32{ false };
	std::vector<IMAGE_DATA_DIRECTORY> m_dataDirs;
	std::vector<IMAGE_SECTION_HEADER> m_sections;
public:
	CListCtrl m_listDLL;
	std::vector<ImportEntry> m_imports;
	afx_msg void OnLvnItemchangedListInfo(NMHDR* pNMHDR, LRESULT* pResult);
};

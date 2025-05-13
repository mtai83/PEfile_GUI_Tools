#include "pch.h"
#include "framework.h"
#include "PEfile_GUI_tools.h"
#include "PEfile_GUI_toolsDlg.h"
#include "afxdialogex.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CString filePath;
bool isPE32 = false;
DWORD importRVA = 0;

LPCTSTR directoryNames[] = {
    _T("Export Directory"), _T("Import Directory"), _T("Resource Directory"), _T("Exception Directory"),
    _T("Security Directory"), _T("Relocation Directory"), _T("Debug Directory"), _T("Architecture Directory"),
    _T("Reserved"), _T("TLS Directory"), _T("Config Directory"), _T("Bound Import Directory"),
    _T("IAT Directory"), _T("Delay Import Directory"), _T(".NET Metadata Directory")
};


// CPEfileGUItoolsDlg dialog

CPEfileGUItoolsDlg::CPEfileGUItoolsDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PEFILE_GUI_TOOLS_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPEfileGUItoolsDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_Tree_PEfile, m_TreeCtrl);
    DDX_Control(pDX, IDC_BTN_SELECT_FILE, BTN_SELECT_FILE);
    DDX_Control(pDX, IDC_EDIT_FILE_PATH, m_editFilePath);
    DDX_Control(pDX, IDC_LIST_INFO, m_listInfo);
    DDX_Control(pDX, IDC_LIST_DLL, m_listDLL);
}

BEGIN_MESSAGE_MAP(CPEfileGUItoolsDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(TVN_SELCHANGED, IDC_Tree_PEfile, &CPEfileGUItoolsDlg::OnTvnSelchangedTreePefile)
	ON_BN_CLICKED(IDC_BTN_SELECT_FILE, &CPEfileGUItoolsDlg::OnBnClickedBtnSelectFile)
    ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_INFO, &CPEfileGUItoolsDlg::OnLvnItemchangedListInfo)
END_MESSAGE_MAP()

void CPEfileGUItoolsDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CPEfileGUItoolsDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

DWORD RvaToOffset(DWORD rva, IMAGE_SECTION_HEADER* sections, int sectionCount) {
    for (int i = 0; i < sectionCount; i++) {
        DWORD sectionVA = sections[i].VirtualAddress;
        DWORD sectionSize = sections[i].Misc.VirtualSize;
        if (rva >= sectionVA && rva < sectionVA + sectionSize) {
            return rva - sectionVA + sections[i].PointerToRawData;
        }
    }
    return 0; 
}

void CPEfileGUItoolsDlg::OnBnClickedBtnSelectFile()
{
    // Tạo đối tượng CFileDialog để chọn file
    CFileDialog dlg(TRUE, _T("exe"), NULL, OFN_FILEMUSTEXIST, _T("Executable Files (*.exe)|*.exe|All Files (*.*)|*.*||"));
    m_listInfo.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    // Hiển thị hộp thoại
    if (dlg.DoModal() == IDOK)
    {
        m_TreeCtrl.DeleteAllItems();
        m_listInfo.DeleteAllItems();
        while (m_listInfo.DeleteColumn(0));
        // Lấy đường dẫn file đã chọn
        filePath = dlg.GetPathName();

        // Hiển thị đường dẫn file lên một CEdit control
        m_editFilePath.SetWindowTextW(filePath);


        HTREEITEM hRoot = m_TreeCtrl.InsertItem(L"PE File Structure");

        HTREEITEM hDOS = m_TreeCtrl.InsertItem(L"DOS Header", hRoot);
        HTREEITEM hNT = m_TreeCtrl.InsertItem(L"NT Headers", hRoot);
        HTREEITEM hFileHeader = m_TreeCtrl.InsertItem(L"File Header", hNT);
        HTREEITEM hOptionalHeader = m_TreeCtrl.InsertItem(L"Optional Header", hNT);
        HTREEITEM hDataDirectory = m_TreeCtrl.InsertItem(L"Data Directory", hOptionalHeader);
        HTREEITEM hSections = m_TreeCtrl.InsertItem(L"Section Headers", hRoot);
        HTREEITEM hImportDirectory = m_TreeCtrl.InsertItem(L"Import Directory", hRoot);

        m_TreeCtrl.Expand(hRoot, TVE_EXPAND);

    }
}

bool CPEfileGUItoolsDlg::ReadPEheader(FILE* file, IMAGE_FILE_HEADER& fileHeader, DWORD& peSignature) {
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, file) != 1 ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        fclose(file);
        AfxMessageBox(L"Không phải PE file hợp lệ.", MB_OK | MB_ICONERROR);
        return false;
    }
    fseek(file, dosHeader.e_lfanew, SEEK_SET);
    
    fread(&peSignature, sizeof(DWORD), 1, file);
    if (peSignature != IMAGE_NT_SIGNATURE) {
        AfxMessageBox(L"Invalid PE Signature", MB_OK | MB_ICONINFORMATION);
        return false;
    }
    
    fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, file);
    int index = 0;

    CString str;

    str.Format(_T("0x%X"), fileHeader.Machine);
    m_listInfo.InsertItem(index, _T("Machine"));
    m_listInfo.SetItemText(index++, 1, str);

    str.Format(_T("%d"), fileHeader.NumberOfSections);
    m_listInfo.InsertItem(index, _T("Number of Sections"));
    m_listInfo.SetItemText(index++, 1, str);

    str.Format(_T("0x%X"), fileHeader.TimeDateStamp);
    m_listInfo.InsertItem(index, _T("TimeDateStamp"));
    m_listInfo.SetItemText(index++, 1, str);

    str.Format(_T("%d"), fileHeader.SizeOfOptionalHeader);
    m_listInfo.InsertItem(index, _T("Size of Optional Header"));
    m_listInfo.SetItemText(index++, 1, str);

    str.Format(_T("0x%X"), fileHeader.Characteristics);
    m_listInfo.InsertItem(index, _T("Characteristics"));
    m_listInfo.SetItemText(index++, 1, str);

    return true;
}

bool CPEfileGUItoolsDlg::ReadOptionalHeader(FILE* file, IMAGE_FILE_HEADER& fileHeader, DWORD& peSignature) {
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, file) != 1 ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        fclose(file);
        AfxMessageBox(L"Không phải PE file hợp lệ.", MB_OK | MB_ICONERROR);
        return false;
    }
    fseek(file, dosHeader.e_lfanew, SEEK_SET);

    fread(&peSignature, sizeof(DWORD), 1, file);
    if (peSignature != IMAGE_NT_SIGNATURE) {
        AfxMessageBox(L"Invalid PE Signature", MB_OK | MB_ICONINFORMATION);
        return false;
    }

    fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, file);


    if (fileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
        IMAGE_OPTIONAL_HEADER32 optionalHeader;
        fread(&optionalHeader, sizeof(optionalHeader), 1, file);
        isPE32 = true;
        importRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        
        int index = 0;
        CString str;

        str.Format(_T("0x%X"), optionalHeader.Magic);
        m_listInfo.InsertItem(index, _T("Magic"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.MajorLinkerVersion);
        m_listInfo.InsertItem(index, _T("MajorLinkerVersion"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.MinorLinkerVersion);
        m_listInfo.InsertItem(index, _T("MinorLinkerVersion"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfCode);
        m_listInfo.InsertItem(index, _T("SizeOfCode"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfInitializedData);
        m_listInfo.InsertItem(index, _T("SizeOfInitializedData"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfUninitializedData);
        m_listInfo.InsertItem(index, _T("SizeOfUninitializedData"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.Magic);
        m_listInfo.InsertItem(index, _T("Magic"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.AddressOfEntryPoint);
        m_listInfo.InsertItem(index, _T("AddressOfEntryPoint"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.BaseOfCode);
        m_listInfo.InsertItem(index, _T("BaseOfCode"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.ImageBase);
        m_listInfo.InsertItem(index, _T("ImageBase"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SectionAlignment);
        m_listInfo.InsertItem(index, _T("SectionAlignment"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.FileAlignment);
        m_listInfo.InsertItem(index, _T("FileAlignment"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.MajorOperatingSystemVersion);
        m_listInfo.InsertItem(index, _T("MajorOperatingSystemVersion"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.MinorOperatingSystemVersion);
        m_listInfo.InsertItem(index, _T("MinorOperatingSystemVersion"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.MajorImageVersion);
        m_listInfo.InsertItem(index, _T("MajorImageVersion"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.MinorImageVersion);
        m_listInfo.InsertItem(index, _T("MinorImageVersion"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.MajorSubsystemVersion);
        m_listInfo.InsertItem(index, _T("MajorSubsystemVersion"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.MinorSubsystemVersion);
        m_listInfo.InsertItem(index, _T("MinorSubsystemVersion"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.Win32VersionValue);
        m_listInfo.InsertItem(index, _T("Win32VersionValue"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfImage);
        m_listInfo.InsertItem(index, _T("SizeOfImage"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfHeaders);
        m_listInfo.InsertItem(index, _T("SizeOfHeaders"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.CheckSum);
        m_listInfo.InsertItem(index, _T("CheckSum"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.Subsystem);
        m_listInfo.InsertItem(index, _T("Subsystem"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.DllCharacteristics);
        m_listInfo.InsertItem(index, _T("DllCharacteristics"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfStackReserve);
        m_listInfo.InsertItem(index, _T("SizeOfStackReserve"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfStackCommit);
        m_listInfo.InsertItem(index, _T("SizeOfStackCommit"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfHeapReserve);
        m_listInfo.InsertItem(index, _T("SizeOfHeapReserve"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.SizeOfHeapCommit);
        m_listInfo.InsertItem(index, _T("SizeOfHeapCommit"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.LoaderFlags);
        m_listInfo.InsertItem(index, _T("LoaderFlags"));
        m_listInfo.SetItemText(index++, 1, str);

        str.Format(_T("0x%X"), optionalHeader.NumberOfRvaAndSizes);
        m_listInfo.InsertItem(index, _T("NumberOfRvaAndSizes"));
        m_listInfo.SetItemText(index++, 1, str);

    }
    else if (fileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)) {
        IMAGE_OPTIONAL_HEADER64 optionalHeader;
        fread(&optionalHeader, sizeof(optionalHeader), 1, file);
        importRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        
        int index = 0;
        CString str;

        str.Format(_T("0x%X"), optionalHeader.Magic);
        m_listInfo.InsertItem(index, _T("Magic"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.MajorLinkerVersion);
        m_listInfo.InsertItem(index, _T("MajorLinkerVersion"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.MinorLinkerVersion);
        m_listInfo.InsertItem(index, _T("MinorLinkerVersion"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.SizeOfCode);
        m_listInfo.InsertItem(index, _T("SizeOfCode"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.SizeOfInitializedData);
        m_listInfo.InsertItem(index, _T("SizeOfInitializedData"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.SizeOfUninitializedData);
        m_listInfo.InsertItem(index, _T("SizeOfUninitializedData"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.Magic);
        m_listInfo.InsertItem(index, _T("Magic"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.AddressOfEntryPoint);
        m_listInfo.InsertItem(index, _T("AddressOfEntryPoint"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.BaseOfCode);
        m_listInfo.InsertItem(index, _T("BaseOfCode"));
        m_listInfo.SetItemText(index++, 1, str);
       
        str.Format(_T("0x%X"), optionalHeader.ImageBase);
        m_listInfo.InsertItem(index, _T("ImageBase"));
        m_listInfo.SetItemText(index++, 1, str);
      
        str.Format(_T("0x%X"), optionalHeader.SectionAlignment);
        m_listInfo.InsertItem(index, _T("SectionAlignment"));
        m_listInfo.SetItemText(index++, 1, str);
     
        str.Format(_T("0x%X"), optionalHeader.FileAlignment);
        m_listInfo.InsertItem(index, _T("FileAlignment"));
        m_listInfo.SetItemText(index++, 1, str);
       
        str.Format(_T("0x%X"), optionalHeader.MajorOperatingSystemVersion);
        m_listInfo.InsertItem(index, _T("MajorOperatingSystemVersion"));
        m_listInfo.SetItemText(index++, 1, str);
      
        str.Format(_T("0x%X"), optionalHeader.MinorOperatingSystemVersion);
        m_listInfo.InsertItem(index, _T("MinorOperatingSystemVersion"));
        m_listInfo.SetItemText(index++, 1, str);
      
        str.Format(_T("0x%X"), optionalHeader.MajorImageVersion);
        m_listInfo.InsertItem(index, _T("MajorImageVersion"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.MinorImageVersion);
        m_listInfo.InsertItem(index, _T("MinorImageVersion"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.MajorSubsystemVersion);
        m_listInfo.InsertItem(index, _T("MajorSubsystemVersion"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.MinorSubsystemVersion);
        m_listInfo.InsertItem(index, _T("MinorSubsystemVersion"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.Win32VersionValue);
        m_listInfo.InsertItem(index, _T("Win32VersionValue"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.SizeOfImage);
        m_listInfo.InsertItem(index, _T("SizeOfImage"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.SizeOfHeaders);
        m_listInfo.InsertItem(index, _T("SizeOfHeaders"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.CheckSum);
        m_listInfo.InsertItem(index, _T("CheckSum"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.Subsystem);
        m_listInfo.InsertItem(index, _T("Subsystem"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.DllCharacteristics);
        m_listInfo.InsertItem(index, _T("DllCharacteristics"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%llX"), optionalHeader.SizeOfStackReserve);
        m_listInfo.InsertItem(index, _T("SizeOfStackReserve"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%llX"), optionalHeader.SizeOfStackCommit);
        m_listInfo.InsertItem(index, _T("SizeOfStackCommit"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%llX"), optionalHeader.SizeOfHeapReserve);
        m_listInfo.InsertItem(index, _T("SizeOfHeapReserve"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%llX"), optionalHeader.SizeOfHeapCommit);
        m_listInfo.InsertItem(index, _T("SizeOfHeapCommit"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.LoaderFlags);
        m_listInfo.InsertItem(index, _T("LoaderFlags"));
        m_listInfo.SetItemText(index++, 1, str);
        
        str.Format(_T("0x%X"), optionalHeader.NumberOfRvaAndSizes);
        m_listInfo.InsertItem(index, _T("NumberOfRvaAndSizes"));
        m_listInfo.SetItemText(index++, 1, str);
    }
    else {
        printf("Unknown Optional Header size: %d\n", fileHeader.SizeOfOptionalHeader);
        return false;
    }
    return true;
}

bool CPEfileGUItoolsDlg::ReadDataDirecoty(FILE* file, IMAGE_FILE_HEADER& fileHeader, DWORD& peSignature) {
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, file) != 1 ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        fclose(file);
        AfxMessageBox(L"Không phải PE file hợp lệ.", MB_OK | MB_ICONERROR);
        return false;
    }
    fseek(file, dosHeader.e_lfanew, SEEK_SET);

    fread(&peSignature, sizeof(DWORD), 1, file);
    if (peSignature != IMAGE_NT_SIGNATURE) {
        AfxMessageBox(L"Invalid PE Signature", MB_OK | MB_ICONINFORMATION);
        return false;
    }

    fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, file);
    if (fileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
        IMAGE_OPTIONAL_HEADER32 optionalHeader;
        fread(&optionalHeader, sizeof(optionalHeader), 1, file);
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1; i++) {
            CString indexStr, rvaStr, sizeStr;

            indexStr.Format(_T("%s"), directoryNames[i]);
            rvaStr.Format(_T("0x%08X"), optionalHeader.DataDirectory[i].VirtualAddress);
            sizeStr.Format(_T("0x%08X"), optionalHeader.DataDirectory[i].Size);
            int itemIndex = m_listInfo.InsertItem(i, indexStr);
            m_listInfo.SetItemText(itemIndex, 1, rvaStr);
            m_listInfo.SetItemText(itemIndex, 2, sizeStr);
        }
    }
    else {
        IMAGE_OPTIONAL_HEADER64 optionalHeader;
        fread(&optionalHeader, sizeof(optionalHeader), 1, file);
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1; i++) {
            CString indexStr, rvaStr, sizeStr;

            indexStr.Format(_T("%s"), directoryNames[i]);
            rvaStr.Format(_T("0x%08X"), optionalHeader.DataDirectory[i].VirtualAddress);
            sizeStr.Format(_T("0x%08X"), optionalHeader.DataDirectory[i].Size);
            int itemIndex = m_listInfo.InsertItem(i, indexStr);
            m_listInfo.SetItemText(itemIndex, 1, rvaStr);
            m_listInfo.SetItemText(itemIndex, 2, sizeStr);
        }
    }
}
 
bool CPEfileGUItoolsDlg::ReadSectionTable(FILE* file, IMAGE_FILE_HEADER& fileHeader, DWORD& peSignature)
{
    IMAGE_DOS_HEADER dosHeader;

    // 1) Đọc DOS header từ đầu file
    fseek(file, 0, SEEK_SET);
    if (fread(&dosHeader, sizeof(dosHeader), 1, file) != 1 ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        AfxMessageBox(_T("Không phải PE file hợp lệ."), MB_OK | MB_ICONERROR);
        fclose(file);
        return false;
    }

    // 2) Nhảy tới e_lfanew, đọc PE signature và File Header
    fseek(file, dosHeader.e_lfanew, SEEK_SET);
    if (fread(&peSignature, sizeof(peSignature), 1, file) != 1 ||
        peSignature != IMAGE_NT_SIGNATURE)
    {
        AfxMessageBox(_T("Invalid PE signature."), MB_OK | MB_ICONERROR);
        fclose(file);
        return false;
    }
    if (fread(&fileHeader, sizeof(fileHeader), 1, file) != 1)
    {
        AfxMessageBox(_T("Không đọc được IMAGE_FILE_HEADER."), MB_OK | MB_ICONERROR);
        fclose(file);
        return false;
    }

    // 3) Tính offset của Section Table và nhảy tới đó
    long sectionTableOffset =
        dosHeader.e_lfanew
        + sizeof(DWORD)                    // PE signature
        + sizeof(IMAGE_FILE_HEADER)
        + fileHeader.SizeOfOptionalHeader; // Optional header size
    fseek(file, sectionTableOffset, SEEK_SET);

    // 4) Đọc hết Section Header vào m_sections để tối ưu (hoặc cấp phát tạm như bạn muốn)
    std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
    if (fread(sections.data(),
        sizeof(IMAGE_SECTION_HEADER),
        sections.size(),
        file) != sections.size())
    {
        AfxMessageBox(_T("Không đọc được Section Table."), MB_OK | MB_ICONERROR);
        fclose(file);
        return false;
    }

    // 5) Hiển thị ra List Control
    m_listInfo.DeleteAllItems();
    for (int i = 0; i < (int)sections.size(); ++i)
    {
        auto& sec = sections[i];
        CString name; name.Format(_T("%hs"), sec.Name);
        int idx = m_listInfo.InsertItem(i, name);

        CString tmp;
        tmp.Format(_T("0x%08X"), sec.VirtualAddress);
        m_listInfo.SetItemText(idx, 1, tmp);

        tmp.Format(_T("0x%08X"), sec.Misc.VirtualSize);
        m_listInfo.SetItemText(idx, 2, tmp);

        tmp.Format(_T("0x%08X"), sec.PointerToRawData);
        m_listInfo.SetItemText(idx, 3, tmp);

        tmp.Format(_T("0x%08X"), sec.SizeOfRawData);
        m_listInfo.SetItemText(idx, 4, tmp);

        tmp.Format(_T("0x%08X"), sec.PointerToRelocations);
        m_listInfo.SetItemText(idx, 5, tmp);

        tmp.Format(_T("0x%08X"), sec.NumberOfRelocations);
        m_listInfo.SetItemText(idx, 6, tmp);

        tmp.Format(_T("0x%08X"), sec.PointerToLinenumbers);
        m_listInfo.SetItemText(idx, 7, tmp);

        tmp.Format(_T("0x%08X"), sec.NumberOfLinenumbers);
        m_listInfo.SetItemText(idx, 8, tmp);

        tmp.Format(_T("0x%08X"), sec.Characteristics);
        m_listInfo.SetItemText(idx, 9, tmp);
    }

    fclose(file);
    return true;
}

void CPEfileGUItoolsDlg::ReadImportDirectory(FILE* file) {
    m_imports.clear();
    m_listInfo.DeleteAllItems();

    // --- Đọc DOS/NT/Header/Sections như trước ---
    IMAGE_DOS_HEADER dos;
    fseek(file, 0, SEEK_SET);
    fread(&dos, sizeof(dos), 1, file);
    fseek(file, dos.e_lfanew, SEEK_SET);

    DWORD peSig; IMAGE_FILE_HEADER fh;
    fread(&peSig, sizeof(peSig), 1, file);
    fread(&fh, sizeof(fh), 1, file);

    bool isPE32 = (fh.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32));
    DWORD importRVA;
    if (isPE32) {
        IMAGE_OPTIONAL_HEADER32 oh32; fread(&oh32, sizeof(oh32), 1, file);
        importRVA = oh32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }
    else {
        IMAGE_OPTIONAL_HEADER64 oh64; fread(&oh64, sizeof(oh64), 1, file);
        importRVA = oh64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }

    std::vector<IMAGE_SECTION_HEADER> secs(fh.NumberOfSections);
    long secTblOff = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fh.SizeOfOptionalHeader;
    fseek(file, secTblOff, SEEK_SET);
    fread(secs.data(), sizeof(IMAGE_SECTION_HEADER), secs.size(), file);

    // --- Chèn mỗi DLL vào m_listInfo và lưu vào m_imports ---
    DWORD importOffset = RvaToOffset(importRVA, secs.data(), (int)secs.size());
    for (DWORD d = 0; ; ++d) {
        IMAGE_IMPORT_DESCRIPTOR id;
        fseek(file, importOffset + d * sizeof(id), SEEK_SET);
        if (fread(&id, sizeof(id), 1, file) != 1 || id.Name == 0) break;

        // đọc tên DLL
        DWORD nameOff = RvaToOffset(id.Name, secs.data(), (int)secs.size());
        fseek(file, nameOff, SEEK_SET);
        char buf[256]; fgets(buf, sizeof(buf), file);
        CString dllName(buf);

        // tạo entry mới
        ImportEntry entry;
        entry.dllName = dllName;

        // chèn 1 dòng DLL vào listInfo
        int row = m_listInfo.InsertItem(m_listInfo.GetItemCount(), dllName);

        // đọc tất cả hàm rồi lưu vào entry.functions
        DWORD thunkRVA = id.OriginalFirstThunk ? id.OriginalFirstThunk : id.FirstThunk;
        DWORD thunkOff = RvaToOffset(thunkRVA, secs.data(), (int)secs.size());
        for (int t = 0; ; ++t) {
            ULONGLONG data = 0;
            fseek(file, thunkOff + t * (isPE32 ? sizeof(DWORD) : sizeof(ULONGLONG)), SEEK_SET);
            if (fread(&data, (isPE32 ? sizeof(DWORD) : sizeof(ULONGLONG)), 1, file) != 1 || data == 0)
                break;

            CString fn;
            bool byOrd = isPE32
                ? (data & IMAGE_ORDINAL_FLAG32)
                : (data & IMAGE_ORDINAL_FLAG64);
            if (!byOrd) {
                DWORD hintOff = RvaToOffset((DWORD)data, secs.data(), (int)secs.size());
                fseek(file, hintOff + 2, SEEK_SET);
                char nameBuf[256]; fgets(nameBuf, sizeof(nameBuf), file);
                fn = nameBuf;
            }
            else {
                fn.Format(_T("Ordinal: 0x%X"), DWORD(data & 0xFFFF));
            }

            entry.functions.push_back(fn);
        }

        m_imports.push_back(std::move(entry));
    }
}

void CPEfileGUItoolsDlg::OnLvnItemchangedListInfo(NMHDR* pNMHDR, LRESULT* pResult)
{
    m_listDLL.DeleteAllItems();
    LPNMLISTVIEW info = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
    if (!(info->uChanged & LVIF_STATE)) { *pResult = 0; return; }

    // Chỉ xử lý khi vừa được chọn
    if (info->uNewState & LVIS_SELECTED) {
        int idx = info->iItem;
        if (idx >= 0 && idx < (int)m_imports.size()) {
            // Đổ functions
            const auto& funcs = m_imports[idx].functions;
            for (int i = 0; i < (int)funcs.size(); ++i) {
                m_listDLL.InsertItem(i, funcs[i]);
            }
        }
    }
    *pResult = 0;
}

void CPEfileGUItoolsDlg::OnTvnSelchangedTreePefile(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
    // Lấy item hiện tại được chọn
    HTREEITEM hSelectedItem = m_TreeCtrl.GetSelectedItem();
    m_listInfo.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
   
    FILE* file = nullptr;
    errno_t err = _wfopen_s(&file, filePath, L"rb");
    if (err != 0 || file == nullptr) {
        CString msg;
        msg.Format(L"Không thể mở file:\n%s", filePath);
        AfxMessageBox(msg, MB_OK | MB_ICONERROR);
        *pResult = 0;
        return;
    }

    if (hSelectedItem)
    {
        CString itemText = m_TreeCtrl.GetItemText(hSelectedItem);

        m_listInfo.DeleteAllItems();
        while (m_listInfo.DeleteColumn(0)); 
        m_listDLL.DeleteAllItems();
        while (m_listDLL.DeleteColumn(0));
        if (itemText == _T("DOS Header")) {
            IMAGE_DOS_HEADER dosHeader;
            if (fread(&dosHeader, sizeof(dosHeader), 1, file) != 1 ||
                dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            {
                fclose(file);
                AfxMessageBox(L"Không phải PE file hợp lệ.", MB_OK | MB_ICONERROR);
                return;
            }
            m_listInfo.InsertColumn(0, _T("Member"), LVCFMT_LEFT, 250);
            m_listInfo.InsertColumn(1, _T("Value"), LVCFMT_LEFT, 250);

            CString str;

            str.Format(_T("0x%X"), dosHeader.e_magic);
            m_listInfo.InsertItem(0, _T("e_magic"));
            m_listInfo.SetItemText(0, 1, str);

        }
        else if (itemText == _T("NT Headers")) 
        {
            m_listInfo.InsertColumn(0, _T("Member"), LVCFMT_LEFT, 250);
            m_listInfo.InsertColumn(1, _T("Value"), LVCFMT_LEFT, 250);
            
            IMAGE_DOS_HEADER dosHeader;
            if (fread(&dosHeader, sizeof(dosHeader), 1, file) != 1 ||
                dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            {
                fclose(file);
                AfxMessageBox(L"Không phải PE file hợp lệ.", MB_OK | MB_ICONERROR);
                return;
            }
            fseek(file, dosHeader.e_lfanew, SEEK_SET);
            DWORD peSignature;
            fread(&peSignature, sizeof(DWORD), 1, file);
            if (peSignature != IMAGE_NT_SIGNATURE) {
                AfxMessageBox(L"Invalid PE Signature", MB_OK | MB_ICONINFORMATION);
                return;
            }
            CString str;

            str.Format(_T("0x%X"), peSignature);
            m_listInfo.InsertItem(0, _T("Signature"));
            m_listInfo.SetItemText(0, 1, str);
        }

        else if (itemText == _T("File Header"))
        {
            m_listInfo.InsertColumn(0, _T("Member"), LVCFMT_LEFT, 250);
            m_listInfo.InsertColumn(1, _T("Value"), LVCFMT_LEFT, 250);

            IMAGE_FILE_HEADER fileHeader;
            DWORD peSignature;
            ReadPEheader(file, fileHeader, peSignature);
            fclose(file);
        }
        else if (itemText == _T("Optional Header"))
        {
            m_listInfo.InsertColumn(0, _T("Member"), LVCFMT_LEFT, 250);
            m_listInfo.InsertColumn(1, _T("Value"), LVCFMT_LEFT, 250);
            IMAGE_FILE_HEADER fileHeader;
            DWORD peSignature;
            ReadOptionalHeader(file, fileHeader, peSignature);
            fclose(file);
        }
        else if (itemText == _T("Data Directory"))
        {
            m_listInfo.InsertColumn(0, _T("Member"), LVCFMT_LEFT, 250);
            m_listInfo.InsertColumn(1, _T("Value RVA"), LVCFMT_LEFT, 250);
            m_listInfo.InsertColumn(2, _T("Size"), LVCFMT_LEFT, 250);
            IMAGE_FILE_HEADER fileHeader;
            DWORD peSignature;
            ReadDataDirecoty(file, fileHeader, peSignature);
            fclose(file);
        }
        else if (itemText == _T("Section Headers")) 
        {
            m_listInfo.InsertColumn(0, _T("Tên Section"), LVCFMT_LEFT, 100);
            m_listInfo.InsertColumn(1, _T("Virtual Address"), LVCFMT_LEFT, 80);
            m_listInfo.InsertColumn(2, _T("Virtual Size"), LVCFMT_LEFT, 80);
            m_listInfo.InsertColumn(3, _T("Raw Addr"), LVCFMT_LEFT, 80);
            m_listInfo.InsertColumn(4, _T("Raw Size"), LVCFMT_LEFT, 80);
            m_listInfo.InsertColumn(5, _T("Reloc Addr"), LVCFMT_LEFT, 80);
            m_listInfo.InsertColumn(6, _T("Reloc Num"), LVCFMT_LEFT, 80);
            m_listInfo.InsertColumn(7, _T("Line Addr"), LVCFMT_LEFT, 80);
            m_listInfo.InsertColumn(8, _T("Line Num"), LVCFMT_LEFT, 80);
            m_listInfo.InsertColumn(9, _T("Flags"), LVCFMT_LEFT, 100);
            IMAGE_FILE_HEADER fileHeader;
            DWORD peSignature;   
            ReadSectionTable(file, fileHeader, peSignature);
            fclose(file);
        }
        else if (itemText == _T("Import Directory")) {
            m_listDLL.DeleteAllItems();
            while (m_listDLL.DeleteColumn(0));

            m_listInfo.InsertColumn(0, _T("Module Name"), LVCFMT_LEFT, 250);
            m_listDLL.InsertColumn(0, _T("Function Name"), LVCFMT_LEFT, 250);

            ReadImportDirectory(file);
            fclose(file);

        }
    }

    *pResult = 0;
}
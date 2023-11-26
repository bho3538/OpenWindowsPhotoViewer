
#include <Windows.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Storage.Search.h>
#include <winrt/Windows.System.h>

#include <tlhelp32.h>


BOOL LaunchImageViewer(LPCWSTR path);
LPWSTR __GetParentPath(LPCWSTR path);
void CheckAndSetProcessIntegrityLevel();

INT APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, INT cmdshow) {

    LPWSTR cmdLineW = GetCommandLineW();

    if (!cmdLineW) {
        return -1;
    }

    INT argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmdLineW, &argc);
    if (!argv) {
        return -1;
    }

    if (argc < 2) {
        MessageBoxW(NULL, L"Open Windows Photo App From Command line\n(with next/previous button)\n\nUSAGE : OpenImageViewer.exe <full file path>\nCreated by byungho. (https://github.com/bho3538)", L"INFO", 0);
        LocalFree(argv);
        return -1;
    }

    OutputDebugStringW(argv[1]);

    //if process have admin-rights, ms image viewer not working
    //so down process integrity level high to medium
    CheckAndSetProcessIntegrityLevel();

    if (LaunchImageViewer(argv[1])) {

        for (;;) {
            Sleep(5000);
            BOOL exit = TRUE;
            PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W),0, };
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == INVALID_HANDLE_VALUE) {
                break;
            }

            do {
                if (!wcscmp(L"PhotosApp.exe", pe32.szExeFile) || !wcscmp(L"Microsoft.Photos.exe", pe32.szExeFile) || !wcscmp(L"PictureflectPhotoViewer.exe", pe32.szExeFile)) {
                    exit = FALSE;
                    break;
                }
            } while (Process32NextW(hSnap, &pe32));
            CloseHandle(hSnap);

            if (exit) {
                break;
            }
        }
        LocalFree(argv);
        return 0;
    }
    LocalFree(argv);
    return -1;
}

BOOL LaunchImageViewer(LPCWSTR path) {
    BOOL re = FALSE;
    winrt::Windows::Storage::Search::QueryOptions queryOp(winrt::Windows::Storage::Search::CommonFolderQuery::DefaultQuery);
    winrt::Windows::Storage::StorageFolder parentFolder = NULL;
    winrt::Windows::Storage::StorageFile file = NULL;
    winrt::Windows::System::LauncherOptions launchOp;
    
    if (!path) {
        return FALSE;
    }

    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        OutputDebugStringW(L"File not found\n");
        return FALSE;
    }

    LPWSTR parentPath = __GetParentPath(path);
    if (!parentPath) {
        goto escapeArea;
    }

    parentFolder = winrt::Windows::Storage::StorageFolder::GetFolderFromPathAsync(parentPath).get();
    if (!parentFolder) {
        goto escapeArea;
    }

    launchOp.NeighboringFilesQuery(parentFolder.CreateFileQueryWithOptions(queryOp));

    file = winrt::Windows::Storage::StorageFile::GetFileFromPathAsync(path).get();
    if (!file) {
        goto escapeArea;
    }

    re = winrt::Windows::System::Launcher::LaunchFileAsync(file, launchOp).get();

    escapeArea:

    free(parentPath);
    return re;
}

LPWSTR __GetParentPath(LPCWSTR path) {
    if (!path) {
        return NULL;
    }
    DWORD pathLen = wcslen(path);
    LPWSTR parentPath = (LPWSTR)malloc(sizeof(WCHAR) * (pathLen + 1));
    if (parentPath) {
        wcscpy_s(parentPath, pathLen + 1, path);
        *(wcsrchr(parentPath, '\\')) = 0;
    }
    return parentPath;
}

void CheckAndSetProcessIntegrityLevel() {
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID pMandatorySid = NULL;
    TOKEN_MANDATORY_LABEL tml;
    HANDLE hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hToken)) {
        return;
    }

    if (AllocateAndInitializeSid(&sia, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pMandatorySid))
    {
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pMandatorySid;

        SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL));
        FreeSid(pMandatorySid);
    }

    CloseHandle(hToken);
}
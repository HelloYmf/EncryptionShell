#include <Windows.h>
#include "resource.h"
#include "../PE Module/PeTools.h"
#include <string>
using namespace std;

TCHAR* ShellName = NULL;
TCHAR* SrcName = NULL;

//打开资源管理器获取文件
TCHAR* GetFileName(HWND hwndDlg)
{
	OPENFILENAME stOpenFile;
	//设置过滤器信息
	TCHAR szPeFileExt[30] = TEXT("*.exe;*.dll;*.sys");
	//保存文件名字缓冲区
	TCHAR* szFileName = (TCHAR*)malloc(sizeof(TCHAR) * 256);
	//初始化
	memset(szFileName, 0, 256);
	memset(&stOpenFile, 0, sizeof(OPENFILENAME));
	//设置参数
	stOpenFile.lStructSize = sizeof(OPENFILENAME);
	stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	stOpenFile.hwndOwner = hwndDlg;
	stOpenFile.lpstrFilter = szPeFileExt;
	stOpenFile.lpstrFile = szFileName;
	stOpenFile.nMaxFile = MAX_PATH;
	//获取文件完整路径
	GetOpenFileName(&stOpenFile);
	return szFileName;
}

//主界面回调函数
BOOL CALLBACK DialogMainProc(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message			
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
)
{
	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			return TRUE;
		}
		case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
				case IDC_BUTTON_SHELL:
				{
					//选择Shell文件
					 ShellName = GetFileName(hwndDlg);
					
					//写进对话框
					SendDlgItemMessage(hwndDlg, IDC_EDIT_SHELL, WM_SETTEXT, 0, (DWORD)ShellName);

					return TRUE;
				}
				case IDC_BUTTON_SRC:
				{
					//选择SRC文件
					SrcName = GetFileName(hwndDlg);
					//写进对话框
					SendDlgItemMessage(hwndDlg, IDC_EDIT_SRC, WM_SETTEXT, 0, (DWORD)SrcName);

					return TRUE;
				}
				case IDC_BUTTON_START:
				{
					//把Shell装进缓冲区
					PeInstance ShellPe((PATH)ShellName);
					//把Src装进缓冲区
					PeInstance SrcPe((PATH)SrcName);
					//壳源PE新增一个节
					ShellPe.AddSeaction(SrcPe.GetSize());
					//把目标文件追加进缓冲区中新增节中
					ShellPe.AddDataToNewSection(SrcPe.GetBufferInstance(), SrcPe.GetSize());
					//对目标文件部分进行加密

					//从缓冲区写回文件
					TCHAR NewName[256] = { 0 };
					SrcName[strlen(SrcName) - 3] = 0;
					strcpy(NewName, SrcName);
					strcat(NewName, TEXT("_Shell.exe"));
					ShellPe.Save(NewName,2);

					MessageBox(hwndDlg, TEXT("加壳成功！"), TEXT("提示："), MB_OK);
					
					return TRUE;
				}
			}

			return TRUE;
		}
	
		case WM_CLOSE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
	}
	return FALSE;
}

//主函数
int CALLBACK WinMain(
	_In_  HINSTANCE hInstance,
	_In_  HINSTANCE hPrevInstance,
	_In_  LPSTR lpCmdLine,
	_In_  int nCmdShow
	)
{
	//加载主界面Dialog
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogMainProc);

	//打印错误代码
	DWORD errorCode = GetLastError();
	return 0;
}
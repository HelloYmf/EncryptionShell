#include <Windows.h>
#include "resource.h"
#include "../PE Module/PeTools.h"
#include <string>
using namespace std;

TCHAR* ShellName = NULL;
TCHAR* SrcName = NULL;

//����Դ��������ȡ�ļ�
TCHAR* GetFileName(HWND hwndDlg)
{
	OPENFILENAME stOpenFile;
	//���ù�������Ϣ
	TCHAR szPeFileExt[30] = TEXT("*.exe;*.dll;*.sys");
	//�����ļ����ֻ�����
	TCHAR* szFileName = (TCHAR*)malloc(sizeof(TCHAR) * 256);
	//��ʼ��
	memset(szFileName, 0, 256);
	memset(&stOpenFile, 0, sizeof(OPENFILENAME));
	//���ò���
	stOpenFile.lStructSize = sizeof(OPENFILENAME);
	stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	stOpenFile.hwndOwner = hwndDlg;
	stOpenFile.lpstrFilter = szPeFileExt;
	stOpenFile.lpstrFile = szFileName;
	stOpenFile.nMaxFile = MAX_PATH;
	//��ȡ�ļ�����·��
	GetOpenFileName(&stOpenFile);
	return szFileName;
}

//������ص�����
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
					//ѡ��Shell�ļ�
					 ShellName = GetFileName(hwndDlg);
					
					//д���Ի���
					SendDlgItemMessage(hwndDlg, IDC_EDIT_SHELL, WM_SETTEXT, 0, (DWORD)ShellName);

					return TRUE;
				}
				case IDC_BUTTON_SRC:
				{
					//ѡ��SRC�ļ�
					SrcName = GetFileName(hwndDlg);
					//д���Ի���
					SendDlgItemMessage(hwndDlg, IDC_EDIT_SRC, WM_SETTEXT, 0, (DWORD)SrcName);

					return TRUE;
				}
				case IDC_BUTTON_START:
				{
					//��Shellװ��������
					PeInstance ShellPe((PATH)ShellName);
					//��Srcװ��������
					PeInstance SrcPe((PATH)SrcName);
					//��ԴPE����һ����
					ShellPe.AddSeaction(SrcPe.GetSize());
					//��Ŀ���ļ�׷�ӽ�����������������
					ShellPe.AddDataToNewSection(SrcPe.GetBufferInstance(), SrcPe.GetSize());
					//��Ŀ���ļ����ֽ��м���

					//�ӻ�����д���ļ�
					TCHAR NewName[256] = { 0 };
					SrcName[strlen(SrcName) - 3] = 0;
					strcpy(NewName, SrcName);
					strcat(NewName, TEXT("_Shell.exe"));
					ShellPe.Save(NewName,2);

					MessageBox(hwndDlg, TEXT("�ӿǳɹ���"), TEXT("��ʾ��"), MB_OK);
					
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

//������
int CALLBACK WinMain(
	_In_  HINSTANCE hInstance,
	_In_  HINSTANCE hPrevInstance,
	_In_  LPSTR lpCmdLine,
	_In_  int nCmdShow
	)
{
	//����������Dialog
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogMainProc);

	//��ӡ�������
	DWORD errorCode = GetLastError();
	return 0;
}
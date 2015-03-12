
#include "GuiUtil.h"

void PullWindowToTopWithActive(HWND hWnd)
{
	if(::GetForegroundWindow() != hWnd)
	{
		HWND hActiveWnd = ::GetForegroundWindow();
		if(hActiveWnd != nullptr)
		{
			DWORD dwThId = GetWindowThreadProcessId(hActiveWnd, nullptr);
			DWORD dwCurrentThId = GetCurrentThreadId();
			if(dwCurrentThId != dwThId)
			{
				if(AttachThreadInput(dwCurrentThId, dwThId, TRUE))
				{
					if(BringWindowToTop(hWnd) == FALSE)
					{
						DebugBreak();
					}
					AttachThreadInput(dwCurrentThId, dwThId, FALSE);
				}
			}
		}
	}
}

void PullWindowToTopWithInactive(HWND hWnd)
{
	// �ֻ��� ������� �����Ͽ� ������ ������ ������ �Ѵ�. 
	::SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
	// �ֻ��� ������ �Ӽ��� �����Ѵ�. ������ ������� �ٸ� �����캸�� �տ� �����Ѵ�. 
	::SetWindowPos(hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
}

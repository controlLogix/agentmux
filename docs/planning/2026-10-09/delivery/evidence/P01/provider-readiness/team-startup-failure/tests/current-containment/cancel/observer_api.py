import ctypes as c
from ctypes import wintypes as w
k=c.WinDLL('kernel32',use_last_error=True)
class STARTUPINFO(c.Structure):
    _fields_=[('cb',w.DWORD),('lpReserved',w.LPWSTR),('lpDesktop',w.LPWSTR),('lpTitle',w.LPWSTR),('dwX',w.DWORD),('dwY',w.DWORD),('dwXSize',w.DWORD),('dwYSize',w.DWORD),('dwXCountChars',w.DWORD),('dwYCountChars',w.DWORD),('dwFillAttribute',w.DWORD),('dwFlags',w.DWORD),('wShowWindow',w.WORD),('cbReserved2',w.WORD),('lpReserved2',c.POINTER(c.c_ubyte)),('hStdInput',w.HANDLE),('hStdOutput',w.HANDLE),('hStdError',w.HANDLE)]
class PROCESSINFO(c.Structure):
    _fields_=[('hProcess',w.HANDLE),('hThread',w.HANDLE),('dwProcessId',w.DWORD),('dwThreadId',w.DWORD)]
class BASICLIMIT(c.Structure):
    _fields_=[('PerProcessUserTimeLimit',c.c_longlong),('PerJobUserTimeLimit',c.c_longlong),('LimitFlags',w.DWORD),('MinimumWorkingSetSize',c.c_size_t),('MaximumWorkingSetSize',c.c_size_t),('ActiveProcessLimit',w.DWORD),('Affinity',c.c_size_t),('PriorityClass',w.DWORD),('SchedulingClass',w.DWORD)]
class IOCOUNTERS(c.Structure):
    _fields_=[(n,c.c_ulonglong) for n in ['ReadOperationCount','WriteOperationCount','OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount']]
class EXTENDEDLIMIT(c.Structure):
    _fields_=[('BasicLimitInformation',BASICLIMIT),('IoInfo',IOCOUNTERS),('ProcessMemoryLimit',c.c_size_t),('JobMemoryLimit',c.c_size_t),('PeakProcessMemoryUsed',c.c_size_t),('PeakJobMemoryUsed',c.c_size_t)]
for name,args,ret in [
 ('CreateJobObjectW',[c.c_void_p,w.LPCWSTR],w.HANDLE),
 ('SetInformationJobObject',[w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL),
 ('CreateProcessW',[w.LPCWSTR,w.LPWSTR,c.c_void_p,c.c_void_p,w.BOOL,w.DWORD,c.c_void_p,w.LPCWSTR,c.POINTER(STARTUPINFO),c.POINTER(PROCESSINFO)],w.BOOL),
 ('AssignProcessToJobObject',[w.HANDLE,w.HANDLE],w.BOOL),
 ('ResumeThread',[w.HANDLE],w.DWORD),
 ('OpenProcess',[w.DWORD,w.BOOL,w.DWORD],w.HANDLE),
 ('IsProcessInJob',[w.HANDLE,w.HANDLE,c.POINTER(w.BOOL)],w.BOOL),
 ('WaitForSingleObject',[w.HANDLE,w.DWORD],w.DWORD),
 ('TerminateJobObject',[w.HANDLE,w.UINT],w.BOOL),
 ('TerminateProcess',[w.HANDLE,w.UINT],w.BOOL),
 ('GetExitCodeProcess',[w.HANDLE,c.POINTER(w.DWORD)],w.BOOL),
 ('CloseHandle',[w.HANDLE],w.BOOL)]:
    f=getattr(k,name);f.argtypes=args;f.restype=ret


k.GetCurrentProcess.restype=w.HANDLE
k.GetStdHandle.argtypes=[w.DWORD];k.GetStdHandle.restype=w.HANDLE
k.DuplicateHandle.argtypes=[w.HANDLE,w.HANDLE,w.HANDLE,c.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD];k.DuplicateHandle.restype=w.BOOL
k.GetFileType.argtypes=[w.HANDLE];k.GetFileType.restype=w.DWORD


class BASICACCOUNTING(c.Structure):
    _fields_=[('TotalUserTime',c.c_longlong),('TotalKernelTime',c.c_longlong),('ThisPeriodTotalUserTime',c.c_longlong),('ThisPeriodTotalKernelTime',c.c_longlong),('TotalPageFaultCount',w.DWORD),('TotalProcesses',w.DWORD),('ActiveProcesses',w.DWORD),('TotalTerminatedProcesses',w.DWORD)]
k.QueryInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.c_void_p];k.QueryInformationJobObject.restype=w.BOOL


k.OpenJobObjectW.argtypes=[w.DWORD,w.BOOL,w.LPCWSTR];k.OpenJobObjectW.restype=w.HANDLE

k.GetConsoleWindow.argtypes=[];k.GetConsoleWindow.restype=w.HWND

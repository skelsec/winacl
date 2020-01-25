import enum
from winacl.functions.defines import *
from winacl.functions.kernel32 import GetLastError, LocalFree
from winacl.functions.membuff import MemoryBuffer
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.sid import SID
from winacl.functions.constants import SE_OBJECT_TYPE

def win_succ_check(result, func, arguments):
	if result != 0:
		raise ctypes.WinError(result)
	return result

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/23e75ca3-98fd-4396-84e5-86cd9d40d343
OWNER_SECURITY_INFORMATION = 0x00000001 #The owner identifier of the object is being referenced.
GROUP_SECURITY_INFORMATION = 0x00000002 #The primary group identifier of the object is being referenced.
DACL_SECURITY_INFORMATION = 0x00000004 #The DACL of the object is being referenced.
SACL_SECURITY_INFORMATION = 0x00000008 #The SACL of the object is being referenced.
LABEL_SECURITY_INFORMATION = 0x00000010 #The mandatory integrity label is being referenced.
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000 #The SACL inherits access control entries (ACEs) from the parent object.
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000 #The DACL inherits ACEs from the parent object.
PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000 #The SACL cannot inherit ACEs.
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000 #The DACL cannot inherit ACEs.
ATTRIBUTE_SECURITY_INFORMATION = 0x00000020 #A SYSTEM_RESOURCE_ATTRIBUTE_ACE (section 2.4.4.15) is being referenced.
SCOPE_SECURITY_INFORMATION = 0x00000040 #A SYSTEM_SCOPED_POLICY_ID_ACE (section 2.4.4.16) is being referenced.
PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080 #Reserved.
BACKUP_SECURITY_INFORMATION = 0x00010000 #The security descriptor is being accessed for use in a backup operation.


READ_CONTROL                     = 0x00020000

# EnumServicesStatusEx() service type filters (in addition to actual types)
SERVICE_DRIVER = 0x0000000B # SERVICE_KERNEL_DRIVER and SERVICE_FILE_SYSTEM_DRIVER
SERVICE_WIN32  = 0x00000030 # SERVICE_WIN32_OWN_PROCESS and SERVICE_WIN32_SHARE_PROCESS

# EnumServicesStatusEx() service state filters
SERVICE_ACTIVE    = 1
SERVICE_INACTIVE  = 2
SERVICE_STATE_ALL = 3


SC_HANDLE = HANDLE

SERVICE_ALL_ACCESS           = 0xF01FF
SERVICE_QUERY_CONFIG         = 0x0001
SERVICE_CHANGE_CONFIG        = 0x0002
SERVICE_QUERY_STATUS         = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008
SERVICE_START                = 0x0010
SERVICE_STOP                 = 0x0020
SERVICE_PAUSE_CONTINUE       = 0x0040
SERVICE_INTERROGATE          = 0x0080
SERVICE_USER_DEFINED_CONTROL = 0x0100

SC_MANAGER_ALL_ACCESS           = 0xF003F
SC_MANAGER_CONNECT              = 0x0001
SC_MANAGER_CREATE_SERVICE       = 0x0002
SC_MANAGER_ENUMERATE_SERVICE    = 0x0004
SC_MANAGER_LOCK                 = 0x0008
SC_MANAGER_QUERY_LOCK_STATUS    = 0x0010
SC_MANAGER_MODIFY_BOOT_CONFIG   = 0x0020







# https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo

# DWORD GetSecurityInfo(
#  HANDLE               handle,
#  SE_OBJECT_TYPE       ObjectType,
#  SECURITY_INFORMATION SecurityInfo,
#  PSID                 *ppsidOwner,
#  PSID                 *ppsidGroup,
#  PACL                 *ppDacl,
#  PACL                 *ppSacl,
#  PSECURITY_DESCRIPTOR *ppSecurityDescriptor
#);

def GetSecurityInfo(handle_obj, obj_type, info_req):
	_GetSecurityInfo = windll.advapi32.GetSecurityInfo
	_GetSecurityInfo.argtypes = [HANDLE, DWORD, DWORD, PVOID, PVOID, PVOID, PVOID, PVOID] #[HANDLE, SE_OBJECT_TYPE, DWORD, PSID, PSID, PACL, PACL, PSECURITY_DESCRIPTOR]
	_GetSecurityInfo.restype  = DWORD
	_GetSecurityInfo.errcheck = win_succ_check

	ppsidOwner = None
	ppsidGroup = None
	ppDacl = None
	ppSacl = None
	ppSecurityDescriptor = ctypes.pointer(ctypes.c_uint(0))

	ret = _GetSecurityInfo(handle_obj, obj_type, info_req, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ctypes.byref(ppSecurityDescriptor))
	pSecurityDescriptor = ppSecurityDescriptor.contents
	buff = MemoryBuffer(ctypes.addressof(ppSecurityDescriptor.contents))	
	sd = SECURITY_DESCRIPTOR.from_buffer(buff, obj_type)
	LocalFree(ppSecurityDescriptor)
	return sd

def LookupAccountSidW(lpSystemName, sid_data):
	_LookupAccountSidW = windll.advapi32.LookupAccountSidW
	_LookupAccountSidW.argtypes = [LPSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, LPDWORD]
	_LookupAccountSidW.restype  = bool

	cchName = DWORD(0)
	cchReferencedDomainName = DWORD(0)
	peUse = DWORD(0)
	lpSid = ctypes.create_string_buffer(sid_data, len(sid_data))
	_LookupAccountSidW(lpSystemName, lpSid, None, byref(cchName), None, byref(cchReferencedDomainName), byref(peUse))
	error = GetLastError()
	if error != ERROR_INSUFFICIENT_BUFFER:
		raise ctypes.WinError(error)
	lpName = ctypes.create_unicode_buffer(u'', cchName.value + 1)
	lpReferencedDomainName = ctypes.create_unicode_buffer(u'', cchReferencedDomainName.value + 1)
	success = _LookupAccountSidW(lpSystemName, lpSid, lpName, byref(cchName), lpReferencedDomainName, byref(cchReferencedDomainName), byref(peUse))
	if not success:
		raise ctypes.WinError()
	return lpName.value, lpReferencedDomainName.value, peUse.value

def LookupAccountNameW(lpSystemName, accountname):
	_LookupAccountNameW = windll.advapi32.LookupAccountNameW
	_LookupAccountNameW.argtypes = [LPWSTR, LPWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, LPDWORD]
	_LookupAccountNameW.restype  = BOOL

	cbSid = DWORD(0)
	cchReferencedDomainName = DWORD(0)
	peUse = DWORD(0)
	lpAccountName = ctypes.create_unicode_buffer(accountname)
	_LookupAccountNameW(lpSystemName, lpAccountName, None, byref(cbSid), None, byref(cchReferencedDomainName), byref(peUse))
	error = GetLastError()
	if error != ERROR_INSUFFICIENT_BUFFER:
		raise(ctypes.WinError(error))
	sid = ctypes.create_string_buffer(b'', cbSid.value)
	psid = ctypes.cast(ctypes.pointer(sid), PSID)
	lpReferencedDomainName = ctypes.create_unicode_buffer(u'', cchReferencedDomainName.value + 1)
	success = _LookupAccountNameW(lpSystemName, lpAccountName, psid, byref(cbSid), lpReferencedDomainName, byref(cchReferencedDomainName), byref(peUse))
	if not success:
		raise ctypes.WinError()
	
	buff = MemoryBuffer(psid.value)
	sid = SID.from_buffer(buff)
	LocalFree(psid)
	return sid, lpReferencedDomainName.value, peUse.value


# https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsecuritydescriptortostringsecuritydescriptorw
# https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
# https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
SDDL_REVISION_1 = 1

def ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, req_info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION):
	_ConvertSecurityDescriptorToStringSecurityDescriptorW = windll.advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
	_ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [PVOID, DWORD, DWORD, PVOID, PULONG]
	_ConvertSecurityDescriptorToStringSecurityDescriptorW.restype  = DWORD
	_ConvertSecurityDescriptorToStringSecurityDescriptorW.errcheck  = RaiseIfZero

	pstr = ctypes.pointer(ctypes.c_uint(0))
	pstrsize = ctypes.c_uint(0)

	_ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, SDDL_REVISION_1, req_info, byref(pstr), byref(pstrsize))

	res = ctypes.string_at(pstr, pstrsize.value*2) #multiply by two because the size is not in bytes but in character counts and each char is 2 bytes.... fuck you microsoft
	LocalFree(pstr)
	return res.decode('utf-16-le')

#BOOL QueryServiceObjectSecurity(
#  SC_HANDLE            hService,
#  SECURITY_INFORMATION dwSecurityInformation,
#  PSECURITY_DESCRIPTOR lpSecurityDescriptor,
#  DWORD                cbBufSize,
#  LPDWORD              pcbBytesNeeded
#);

def QueryServiceObjectSecurity(hService, dwSecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, with_sd = False):
	_QueryServiceObjectSecurity = windll.advapi32.QueryServiceObjectSecurity
	_QueryServiceObjectSecurity.argtypes = [SC_HANDLE, DWORD, PVOID, DWORD, LPDWORD]
	_QueryServiceObjectSecurity.restype  = DWORD
	#_QueryServiceObjectSecurity.errcheck = RaiseIfZero

	#first we get the size
	lpSecurityDescriptor = None
	cbBufSize = DWORD(0)
	pcbBytesNeeded = DWORD(0)

	correct_length = 0
	res = _QueryServiceObjectSecurity(hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize, pcbBytesNeeded)
	if res == 0:
		#getting the correct length
		correct_length = pcbBytesNeeded.value
	
	lpSecurityDescriptor = ctypes.create_string_buffer(correct_length)
	cbBufSize = DWORD(correct_length)
	pcbBytesNeeded = DWORD(0)

	res = _QueryServiceObjectSecurity(hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize, pcbBytesNeeded)
	if res == 0:
		raise ctypes.WinError(result)
	buff = ctypes.string_at(lpSecurityDescriptor, pcbBytesNeeded.value)
	sd = SECURITY_DESCRIPTOR.from_bytes(buff)

	if with_sd is False:
		 return sd
	else:
		return sd, lpSecurityDescriptor


def OpenSCManagerW(lpMachineName = None, lpDatabaseName = None, dwDesiredAccess = SC_MANAGER_ALL_ACCESS):
	_OpenSCManagerW = windll.advapi32.OpenSCManagerW
	_OpenSCManagerW.argtypes = [LPWSTR, LPWSTR, DWORD]
	_OpenSCManagerW.restype  = SC_HANDLE
	_OpenSCManagerW.errcheck = RaiseIfZero

	hSCObject = _OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess)
	return hSCObject

#
#SC_HANDLE OpenServiceW(
#  SC_HANDLE hSCManager,
#  LPCSTR    lpServiceName,
#  DWORD     dwDesiredAccess
#);

def OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess = SERVICE_ALL_ACCESS):
	_OpenServiceW = windll.advapi32.OpenServiceW
	_OpenServiceW.argtypes = [SC_HANDLE, LPWSTR, DWORD]
	_OpenServiceW.restype  = SC_HANDLE
	_OpenServiceW.errcheck = RaiseIfZero
	return _OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess)

def CloseServiceHandle(hHandle):
    _CloseServiceHandle = windll.advapi32.CloseServiceHandle
    _CloseServiceHandle.argtypes = [HANDLE]
    _CloseServiceHandle.restype  = bool
    _CloseServiceHandle.errcheck = RaiseIfZero
    _CloseServiceHandle(hHandle)


class SERVICE_STATUS(Structure):
	_fields_ = [
		("dwServiceType",               DWORD),
		("dwCurrentState",              DWORD),
		("dwControlsAccepted",          DWORD),
		("dwWin32ExitCode",             DWORD),
		("dwServiceSpecificExitCode",   DWORD),
		("dwCheckPoint",                DWORD),
		("dwWaitHint",                  DWORD),
	]
LPSERVICE_STATUS = POINTER(SERVICE_STATUS)

class ENUM_SERVICE_STATUSW(Structure):
	_fields_ = [
		("lpServiceName", LPWSTR),
		("lpDisplayName", LPWSTR),
		("ServiceStatus", SERVICE_STATUS),
	]
LPENUM_SERVICE_STATUSW = POINTER(ENUM_SERVICE_STATUSW)

def EnumServicesStatusW(hSCManager, dwServiceType = SERVICE_DRIVER | SERVICE_WIN32, dwServiceState = SERVICE_STATE_ALL):
	_EnumServicesStatusW = windll.advapi32.EnumServicesStatusW
	_EnumServicesStatusW.argtypes = [SC_HANDLE, DWORD, DWORD, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD]
	_EnumServicesStatusW.restype  = bool

	cbBytesNeeded    = DWORD(0)
	ServicesReturned = DWORD(0)
	ResumeHandle     = DWORD(0)

	_EnumServicesStatusW(hSCManager, dwServiceType, dwServiceState, None, 0, byref(cbBytesNeeded), byref(ServicesReturned), byref(ResumeHandle))

	Services = []
	success = False
	while GetLastError() == ERROR_MORE_DATA:
		if cbBytesNeeded.value < sizeof(ENUM_SERVICE_STATUSW):
			break
		ServicesBuffer = ctypes.create_string_buffer(b"", cbBytesNeeded.value)
		success = _EnumServicesStatusW(hSCManager, dwServiceType, dwServiceState, byref(ServicesBuffer), sizeof(ServicesBuffer), byref(cbBytesNeeded), byref(ServicesReturned), byref(ResumeHandle))
		if sizeof(ServicesBuffer) < (sizeof(ENUM_SERVICE_STATUSW) * ServicesReturned.value):
			raise ctypes.WinError()
		lpServicesArray = ctypes.cast(ctypes.cast(ctypes.pointer(ServicesBuffer), ctypes.c_void_p), LPENUM_SERVICE_STATUSW)
		for index in range(0, ServicesReturned.value):
			Services.append( lpServicesArray[index].lpServiceName )
		if success: break
	if not success:
		raise ctypes.WinError()

	return Services


HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003
HKEY_PERFORMANCE_DATA = 0x80000004
HKEY_PERFORMANCE_TEXT = 0x80000050
HKEY_PERFORMANCE_NLSTEXT = 0x80000060
HKEY_CURRENT_CONFIG = 0x80000005
HKEY_DYN_DATA = 0x80000006

hive_name_map = {
	'HKLM' : HKEY_LOCAL_MACHINE,
	'HKCU' : HKEY_CURRENT_USER,
	'HKCR' : HKEY_CLASSES_ROOT,
	'HKU'  : HKEY_USERS,
	'HKCC' : HKEY_CURRENT_CONFIG,
	'HKPD' : HKEY_PERFORMANCE_DATA,
}

# https://docs.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys
KEY_ALL_ACCESS = 0xF003F #Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
KEY_CREATE_LINK = 0x0020 #	Reserved for system use.
KEY_CREATE_SUB_KEY = 0x0004 #Required to create a subkey of a registry key.
KEY_ENUMERATE_SUB_KEYS = 0x0008 #Required to enumerate the subkeys of a registry key.
KEY_EXECUTE = 0x20019 #Equivalent to KEY_READ.
KEY_NOTIFY = 0x0010 #Required to request change notifications for a registry key or for subkeys of a registry key.
KEY_QUERY_VALUE = 0x0001 #Required to query the values of a registry key.
KEY_READ = 0x20019 #Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
KEY_SET_VALUE = 0x0002 #Required to create, delete, or set a registry value.
KEY_WOW64_32KEY = 0x0200 #Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. #This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. #Windows 2000: This flag is not supported.
KEY_WOW64_64KEY = 0x0100 #Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. Windows 2000: This flag is not supported.
KEY_WRITE = 0x20006 #Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.


REG_OPTION_RESERVED = 0x0000
REG_OPTION_NON_VOLATILE = 0x0000
REG_OPTION_VOLATILE = 0x0001
REG_OPTION_CREATE_LINK = 0x0002
REG_OPTION_BACKUP_RESTORE = 0x0004
REG_OPTION_OPEN_LINK = 0x0008
#REG_LEGAL_OPTION =
#
#    REG_OPTION_RESERVED |
#    REG_OPTION_NON_VOLATILE | REG_OPTION_CREATE_LINK |
#    REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK

# https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
def RegOpenKeyExW(regkey_handle, subkey_name = None, options = REG_OPTION_NON_VOLATILE, access = KEY_READ):
	_RegOpenKeyExW = windll.advapi32.RegOpenKeyExA
	_RegOpenKeyExW.argtypes = [HANDLE, LPVOID, DWORD, DWORD, PHANDLE]
	_RegOpenKeyExW.restype  = DWORD
	_RegOpenKeyExW.errcheck = RaiseIfNotErrorSuccess

	psubkey = None
	if subkey_name is not None:
		psd = subkey_name.encode('ascii') #despite the W at the end of the function name, it takes ASCII
		psubkey = ctypes.create_string_buffer(psd, len(psd))

	reshandle = HANDLE()
	ret = _RegOpenKeyExW(regkey_handle, psubkey, options, access, ctypes.byref(reshandle))
	return reshandle

# https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
def RegCloseKey(hHandle):
    _RegCloseKey = windll.advapi32.RegCloseKey
    _RegCloseKey.argtypes = [HANDLE]
    _RegCloseKey.restype  = bool
    _RegCloseKey.errcheck = RaiseIfNotErrorSuccess
    _RegCloseKey(hHandle)
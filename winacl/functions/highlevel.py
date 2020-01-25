from winacl.functions.constants import SE_OBJECT_TYPE
from winacl.functions.kernel32 import CloseHandle, CreateFileW, GENERIC_READ, READ_CONTROL, OPEN_EXISTING, FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS
from winacl.functions.advapi32 import LookupAccountNameW, LookupAccountSidW, \
	GetSecurityInfo, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, \
	DACL_SECURITY_INFORMATION, OpenSCManagerW, SC_MANAGER_ENUMERATE_SERVICE, \
	EnumServicesStatusW, OpenServiceW, QueryServiceObjectSecurity, CloseServiceHandle, \
	hive_name_map, RegOpenKeyExW, RegCloseKey
import glob
import os
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

def get_sid_for_user(username):
	sid, domain, use = LookupAccountNameW(None, username)
	return sid

def get_user_for_sid(sid_str):
	sid = SID.from_string(sid_str)
	username, domain, use = LookupAccountSidW(None, sid.to_bytes())
	return '%s\\%s' % (domain, username)

def get_reg_sd(key_handle):
	sd, pdacl = GetSecurityInfo(key_handle, SE_OBJECT_TYPE.SE_REGISTRY_KEY.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	return sd, pdacl

def get_file_sd(file_path):
	file_handle = CreateFileW(file_path, dwDesiredAccess = READ_CONTROL, dwCreationDisposition = OPEN_EXISTING)
	sd = GetSecurityInfo(file_handle, SE_OBJECT_TYPE.SE_FILE_OBJECT.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	CloseHandle(file_handle)
	return sd

def get_directory_sd(dir_path):
	file_handle = CreateFileW(dir_path, dwDesiredAccess = READ_CONTROL, dwCreationDisposition = OPEN_EXISTING, dwFlagsAndAttributes = FILE_ATTRIBUTE_DIRECTORY | FILE_FLAG_BACKUP_SEMANTICS)
	sd = GetSecurityInfo(file_handle, SE_OBJECT_TYPE.SE_FILE_OBJECT.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	CloseHandle(file_handle)
	return sd

def get_dir_file_recursive(dir_path, with_files = False):
	if dir_path[-1] != '\\':
		dir_path += '\\'
	for filename in glob.iglob(dir_path + '**/*', recursive=True):
		if os.path.isdir(filename) is True:
			try:
				yield filename, 'dir', get_directory_sd(filename)
			except:
				yield filename, 'dir', 'ERR'
		elif with_files is True and os.path.isfile(filename) is True:
			try:
				yield filename, 'file', get_file_sd(filename)
			except:
				yield filename, 'file', 'ERR'

def get_servicemanager_sd():
	scm_handle = OpenSCManagerW(dwDesiredAccess = READ_CONTROL )
	sd = QueryServiceObjectSecurity(scm_handle, dwSecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, with_sd = False)
	CloseServiceHandle(scm_handle)
	return sd

def get_service_sd(service_name):
	scm_handle = OpenSCManagerW(dwDesiredAccess = READ_CONTROL | SC_MANAGER_ENUMERATE_SERVICE )
	service_handle = OpenServiceW(scm_handle, service_name, dwDesiredAccess = READ_CONTROL)
	sd = QueryServiceObjectSecurity(service_handle, dwSecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, with_sd = False)
	CloseServiceHandle(scm_handle)
	CloseServiceHandle(service_handle)
	return sd

def enumerate_all_service_sd():
	scm_handle = OpenSCManagerW(dwDesiredAccess = READ_CONTROL | SC_MANAGER_ENUMERATE_SERVICE )
	for service_name in EnumServicesStatusW(scm_handle):
		try:
			service_handle = OpenServiceW(scm_handle, service_name, dwDesiredAccess = READ_CONTROL)
			sd = QueryServiceObjectSecurity(service_handle, dwSecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, with_sd = False)
			yield service_name, sd
		except Exception as e:
			yield service_name, 'err'
		finally:
			try:
				CloseServiceHandle(service_handle)
			except:
				pass
	try:
		CloseServiceHandle(scm_handle)
	except:
		pass

def get_registry_hive_sd(hive_name):
	key_handle = hive_name_map[hive_name]
	sd = GetSecurityInfo(key_handle, SE_OBJECT_TYPE.SE_REGISTRY_KEY.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	return sd

def get_registry_key_sd(reg_path):
	# eg. HKLM\\SAM
	path_elements = reg_path.split('\\')
	reg_handle = hive_name_map[path_elements[0]]
	handles = []
	for name in path_elements[1:-1]:
		reg_handle = RegOpenKeyExW(reg_handle, name)
		handles.append(reg_handle)
	
	sd = GetSecurityInfo(reg_handle, SE_OBJECT_TYPE.SE_REGISTRY_KEY.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	for reg_handle in handles[::-1]:
		RegCloseKey(reg_handle)
	
	return sd

def enumerate_registry_sd(start_pos):
	# TODO: do this
	pass

if __name__ == '__main__':
	
	#regkey = 'HKLM\\SYSTEM\\ControlSet001\\Enum\\HTREE\\ROOT\\0'
	#print(get_registry_key_sd(regkey))
	
	#print(get_registry_hive_sd('HKLM'))

	#path = 'C:\\Users\\victim\\Desktop\\course_winsec_1\\example_3.py'
	#for service_name, sd in enumerate_all_service_sd():
	#	print(service_name)
	
	#print(get_servicemanager_sd())
	#print(get_service_sd('WinRM'))
	
	#for filename, fdtype, sd in get_dir_file_recursive(path, with_files = False):
	#    if isinstance(sd, SECURITY_DESCRIPTOR):
	#        print(filename, fdtype, sd.to_ssdl())
	#    else:
	#        print(filename, fdtype, sd)
	
	
	#sd = get_file_sd(path)
	#print(str(sd))
	#print(sd.to_ssdl())

	#data = bytes.fromhex('01000480d4000000e000000000000000140000000200c00007000000000014000100000001010000000000050b000000000014001500020001010000000000050400000000001400150002000101000000000005060000000000140035000200010100000000000512000000000018003f000f00010200000000000520000000200200000000180001000000010200000000000f02000000010000000000380001000000010a00000000000f0300000000040000b6747a1f9e6814e763514a2a3cd5b771b29878d64c2476dc5c2193100dbadbed010100000000000512000000010100000000000512000000')
	#sd = SECURITY_DESCRIPTOR.from_bytes(data)
	#print(sd)
	#print(sd.to_bytes())
	##print(sd.to_bytes() == data)
	##for i, (o, m) in enumerate(zip(data, sd.to_bytes())):
	##    if o != m:
	##        print(i)  
	#sd2 = SECURITY_DESCRIPTOR.from_bytes(sd.to_bytes())
	#print(sd2)
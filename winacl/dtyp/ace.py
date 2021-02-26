#
# Author:
#  Tamas Jos (@skelsec)
#

# TODO 
# implement https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/21f2b5f0-7376-45bb-bc31-eaa60841dbe9
# implement https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/9020a075-c1af-4b03-930b-ba785743bcab

import io
import enum
from winacl.dtyp.sid import SID, sddl_name_val_map
from winacl.dtyp.guid import GUID
from winacl.functions.constants import SE_OBJECT_TYPE


class ACCESS_MASK(enum.IntFlag):
	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x4000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL = 0x10000000
	MAXIMUM_ALLOWED = 0x02000000
	ACCESS_SYSTEM_SECURITY = 0x01000000
	
class STANDARD_ACCESS_MASK(enum.IntFlag):
	SYNCHRONIZE = 0x00100000
	WRITE_OWNER = 0x00080000
	WRITE_DACL = 0x00040000
	READ_CONTROL = 0x00020000
	DELETE = 0x00010000
	ALL = 0x00100000 | 0x00080000 | 0x00040000 | 0x00020000 | 0x00010000
	EXECUTE = 0x00020000
	READ = 0x00020000
	WRITE = 0x00020000
	REQUIRED = 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000
	
#https://docs.microsoft.com/en-us/previous-versions/tn-archive/ff405675(v%3dmsdn.10)
class ADS_ACCESS_MASK(enum.IntFlag):
	CREATE_CHILD   = 0x00000001 #The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to create this type of child object.
	DELETE_CHILD   = 0x00000002 #The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to delete this type of child object.
	
	ACTRL_DS_LIST  = 0x00000004 #Enumerate a DS object.
	SELF           = 0x00000008 #The ObjectType GUID identifies a validated write.
	READ_PROP      = 0x00000010 #The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to read the property or property set.
	WRITE_PROP     = 0x00000020 #The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to write the property or property set.
	
	DELETE_TREE    = 0x00000040
	LIST_OBJECT    = 0x00000080
	CONTROL_ACCESS = 0x00000100 #The ObjectType GUID identifies an extended access right.
	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x4000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL = 0x10000000
	MAXIMUM_ALLOWED = 0x02000000
	ACCESS_SYSTEM_SECURITY = 0x01000000
	SYNCHRONIZE = 0x00100000
	WRITE_OWNER = 0x00080000
	WRITE_DACL = 0x00040000
	READ_CONTROL = 0x00020000
	DELETE = 0x00010000
	
class FILE_ACCESS_MASK(enum.IntFlag):
	#includes directory access as well
	FILE_READ_DATA = 1 #For a file object, the right to read the corresponding file data. For a directory object, the right to read the corresponding directory data.
	FILE_LIST_DIRECTORY = 1 #	For a directory, the right to list the contents of the directory.
	FILE_ADD_FILE = 2 #For a directory, the right to create a file in the directory.
	FILE_WRITE_DATA = 2#For a file object, the right to write data to the file. For a directory object, the right to create a file in the directory (FILE_ADD_FILE).
	FILE_ADD_SUBDIRECTORY = 4 #For a directory, the right to create a subdirectory.
	FILE_APPEND_DATA = 4 #	For a file object, the right to append data to the file. (For local files, write operations will not overwrite existing data if this flag is specified without FILE_WRITE_DATA.) For a directory object, the right to create a subdirectory (FILE_ADD_SUBDIRECTORY).
	FILE_CREATE_PIPE_INSTANCE = 4 #	For a named pipe, the right to create a pipe.
	FILE_READ_EA = 8 #The right to read extended file attributes.
	FILE_WRITE_EA = 16  #The right to write extended file attributes.
	FILE_EXECUTE = 32  #	For a native code file, the right to execute the file. This access right given to scripts may cause the script to be executable, depending on the script interpreter.
	FILE_TRAVERSE = 32  #For a directory, the right to traverse the directory. By default, users are assigned the BYPASS_TRAVERSE_CHECKING privilege, which ignores the FILE_TRAVERSE access right. See the remarks in File Security and Access Rights for more information.
	FILE_DELETE_CHILD = 64  #For a directory, the right to delete a directory and all the files it contains, including read-only files.
	FILE_READ_ATTRIBUTES = 128 #The right to read file attributes.
	FILE_WRITE_ATTRIBUTES = 256  #The right to write file attributes.
	FILE_ALL_ACCESS = 0x1f01ff #All possible access rights for a file.
	#STANDARD_RIGHTS_READ #Includes READ_CONTROL, which is the right to read the information in the file or directory object's security descriptor. This does not include the information in the SACL.
	#STANDARD_RIGHTS_WRITE #Same as STANDARD_RIGHTS_READ.
	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x4000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL = 0x10000000
	MAXIMUM_ALLOWED = 0x02000000
	ACCESS_SYSTEM_SECURITY = 0x01000000
	SYNCHRONIZE = 0x00100000
	WRITE_OWNER = 0x00080000
	WRITE_DACL = 0x00040000
	READ_CONTROL = 0x00020000
	DELETE = 0x00010000
	ALL = 0x00100000 | 0x00080000 | 0x00040000 | 0x00020000 | 0x00010000
	EXECUTE = 0x00020000
	READ = 0x00020000
	WRITE = 0x00020000
	REQUIRED = 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000
	
#FILE_RIGHTS = ACCESS_MASK + STANDARD_ACCESS_MASK + FILE_ACCESS_MASK

# https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?redirectedfrom=MSDN
class SC_MANAGER_ACCESS_MASK(enum.IntFlag):
	ALL_ACCESS = 0xF003F #Includes STANDARD_RIGHTS_REQUIRED, in addition to all access rights in this table.
	CREATE_SERVICE = 0x0002 #Required to call the CreateService function to create a service object and add it to the database.
	CONNECT = 0x0001  #Required to connect to the service control manager.
	ENUMERATE_SERVICE = 0x0004 #Required to call the EnumServicesStatus or EnumServicesStatusEx function to list the services that are in the database. Required to call the NotifyServiceStatusChange function to receive notification when any service is created or deleted.
	LOCK = 0x0008 #Required to call the LockServiceDatabase function to acquire a lock on the database.
	MODIFY_BOOT_CONFIG = 0x0020 #Required to call the NotifyBootConfigStatus function.
	QUERY_LOCK_STATUS = 0x0010 #	Required to call the QueryServiceLockStatus function to retrieve the lock status information for the database.

	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x4000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL = 0x10000000

# https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?redirectedfrom=MSDN
class SERVICE_ACCESS_MASK(enum.IntFlag):
	SERVICE_ALL_ACCESS = 0xF01FF # Includes STANDARD_RIGHTS_REQUIRED in addition to all access rights in this table.
	SERVICE_CHANGE_CONFIG = 0x0002 # Required to call the ChangeServiceConfig or ChangeServiceConfig2 function to change the service configuration. Because this grants the caller the right to change the executable file that the system runs, it should be granted only to administrators.
	SERVICE_ENUMERATE_DEPENDENTS = 0x0008 # Required to call the EnumDependentServices function to enumerate all the services dependent on the service.
	SERVICE_INTERROGATE = 0x0080 # Required to call the ControlService function to ask the service to report its status immediately.
	SERVICE_PAUSE_CONTINUE = 0x0040 # Required to call the ControlService function to pause or continue the service.
	SERVICE_QUERY_CONFIG = 0x0001 # Required to call the QueryServiceConfig and QueryServiceConfig2 functions to query the service configuration.
	SERVICE_QUERY_STATUS = 0x0004 # Required to call the QueryServiceStatus or QueryServiceStatusEx function to ask the service control manager about the status of the service.
	#Required to call the NotifyServiceStatusChange function to receive notification when a service changes status.
	SERVICE_START = 0x0010 # Required to call the StartService function to start the service.
	SERVICE_STOP = 0x0020 # Required to call the ControlService function to stop the service.
	SERVICE_USER_DEFINED_CONTROL = 0x0100 # Required to call the ControlService function to specify a user-defined control code.

	# TODO : value for ?ACCESS_SYSTEM_SECURITY? 	Required to call the QueryServiceObjectSecurity or SetServiceObjectSecurity function to access the SACL. The proper way to obtain this access is to enable the SE_SECURITY_NAMEprivilege in the caller's current access token, open the handle for ACCESS_SYSTEM_SECURITY access, and then disable the privilege.
	DELETE = 0x10000 #Required to call the DeleteService function to delete the service.
	READ_CONTROL = 0x20000 #Required to call the QueryServiceObjectSecurity function to query the security descriptor of the service object.
	WRITE_DAC = 0x40000 #Required to call the SetServiceObjectSecurity function to modify the Dacl member of the service object's security descriptor.
	WRITE_OWNER = 0x80000 #Required to call the SetServiceObjectSecurity function to modify the Owner and Group members of the service object's security descriptor.

# https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights?redirectedfrom=MSDN
class REGISTRY_ACCESS_MASK(enum.IntFlag):
	KEY_ALL_ACCESS = 0xF003F # Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
	KEY_CREATE_LINK = 0x0020 # Reserved for system use.
	KEY_CREATE_SUB_KEY = 0x0004 # Required to create a subkey of a registry key.
	KEY_ENUMERATE_SUB_KEYS = 0x0008 # Required to enumerate the subkeys of a registry key.
	KEY_EXECUTE = 0x20019 # Equivalent to KEY_READ.
	KEY_NOTIFY = 0x0010 # Required to request change notifications for a registry key or for subkeys of a registry key.
	KEY_QUERY_VALUE = 0x0001 # Required to query the values of a registry key.
	KEY_READ = 0x20019 # Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
	KEY_SET_VALUE = 0x0002 # Required to create, delete, or set a registry value.
	KEY_WOW64_32KEY = 0x0200 # Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. Windows 2000: This flag is not supported.
	KEY_WOW64_64KEY = 0x0100 # Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. Windows 2000: This flag is not supported.
	KEY_WRITE = 0x20006 # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.


#http://www.kouti.com/tables/baseattributes.htm

ExtendedRightsGUID = { 
	'ee914b82-0a98-11d1-adbb-00c04fd8d5cd' : 'Abandon Replication',
	'440820ad-65b4-11d1-a3da-0000f875ae0d' : 'Add GUID',
	'1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd' : 'Allocate Rids',
	'68b1d179-0d15-4d4f-ab71-46152e79a7bc' : 'Allowed to Authenticate',
	'edacfd8f-ffb3-11d1-b41d-00a0c968f939' : 'Apply Group Policy',
	'0e10c968-78fb-11d2-90d4-00c04f79dc55' : 'Certificate-Enrollment',
	'014bf69c-7b3b-11d1-85f6-08002be74fab' : 'Change Domain Master',
	'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' : 'Change Infrastructure Master',
	'bae50096-4752-11d1-9052-00c04fc2d4cf' : 'Change PDC',
	'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' : 'Change Rid Master',
	'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' : 'Change-Schema-Master',
	'e2a36dc9-ae17-47c3-b58b-be34c55ba633' : 'Create Inbound Forest Trust',
	'fec364e0-0a98-11d1-adbb-00c04fd8d5cd' : 'Do Garbage Collection',
	'ab721a52-1e2f-11d0-9819-00aa0040529b' : 'Domain-Administer-Server',
	'69ae6200-7f46-11d2-b9ad-00c04f79f805' : 'Check Stale Phantoms',
	'3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' : 'Allow a DC to create a clone of itself',
	'2f16c4a5-b98e-432c-952a-cb388ba33f2e' : 'Execute Forest Update Script',
	'9923a32a-3607-11d2-b9be-0000f87a36b2' : 'Add/Remove Replica In Domain',
	'4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' : 'Query Self Quota',
	'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' : 'Replicating Directory Changes',
	'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' : 'Replicating Directory Changes All',
	'89e95b76-444d-4c62-991a-0facbeda640c' : 'Replicating Directory Changes In Filtered Set',
	'1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' : 'Manage Replication Topology',
	'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96' : 'Monitor Active Directory Replication',
	'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' : 'Replication Synchronization',
	'05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' : 'Enable Per User Reversibly Encrypted Password',
	'b7b1b3de-ab09-4242-9e30-9980e5d322f7' : 'Generate Resultant Set of Policy (Logging)',
	'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' : 'Generate Resultant Set of Policy (Planning)',
	'7c0e2a7c-a419-48e4-a995-10180aad54dd' : 'Manage Optional Features for Active Directory',
	'ba33815a-4f93-4c76-87f3-57574bff8109' : 'Migrate SID History',
	'b4e60130-df3f-11d1-9c86-006008764d0e' : 'Open Connector Queue',
	'06bd3201-df3e-11d1-9c86-006008764d0e' : 'Allows peeking at messages in the queue.',
	'4b6e08c3-df3c-11d1-9c86-006008764d0e' : 'msmq-Peek-computer-Journal',
	'4b6e08c1-df3c-11d1-9c86-006008764d0e' : 'Peek Dead Letter',
	'06bd3200-df3e-11d1-9c86-006008764d0e' : 'Receive Message',
	'4b6e08c2-df3c-11d1-9c86-006008764d0e' : 'Receive Computer Journal',
	'4b6e08c0-df3c-11d1-9c86-006008764d0e' : 'Receive Dead Letter',
	'06bd3203-df3e-11d1-9c86-006008764d0e' : 'Receive Journal',
	'06bd3202-df3e-11d1-9c86-006008764d0e' : 'Send Message',
	'a1990816-4298-11d1-ade2-00c04fd8d5cd' : 'Open Address List',
	'1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' : 'Read Only Replication Secret Synchronization',
	'45ec5156-db7e-47bb-b53f-dbeb2d03c40f' : 'Reanimate Tombstones',
	'0bc1554e-0a99-11d1-adbb-00c04fd8d5cd' : 'Recalculate Hierarchy',
	'62dd28a8-7f46-11d2-b9ad-00c04f79f805' : 'Recalculate Security Inheritance',
	'ab721a56-1e2f-11d0-9819-00aa0040529b' : 'Receive As',
	'9432c620-033c-4db7-8b58-14ef6d0bf477' : 'Refresh Group Cache for Logons',
	'1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8' : 'Reload SSL/TLS Certificate',
	'7726b9d5-a4b4-4288-a6b2-dce952e80a7f' : 'Run Protect Admin Groups Task',
	'91d67418-0135-4acc-8d79-c08e857cfbec' : 'Enumerate Entire SAM Domain',
	'ab721a54-1e2f-11d0-9819-00aa0040529b' : 'Send As',
	'ab721a55-1e2f-11d0-9819-00aa0040529b' : 'Send To',
	'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501' : 'Unexpire Password',
	'280f369c-67c7-438e-ae98-1d46f3c6f541' : 'Update Password Not Required Bit',
	'be2bb760-7f46-11d2-b9ad-00c04f79f805' : 'Update Schema Cache',
	'ab721a53-1e2f-11d0-9819-00aa0040529b' : 'Change Password',
	'00299570-246d-11d0-a768-00aa006e0529' : 'Reset Password',
}

PropertySets = {
	'72e39547-7b18-11d1-adef-00c04fd8d5cd' : 'DNS Host Name Attributes',
	'b8119fd0-04f6-4762-ab7a-4986c76b3f9a' : 'Other Domain Parameters (for use by SAM)',
	'c7407360-20bf-11d0-a768-00aa006e0529' : 'Domain Password & Lockout Policies',
	'e45795b2-9455-11d1-aebd-0000f80367c1' : 'Phone and Mail Options',
	'59ba2f42-79a2-11d0-9020-00c04fc2d3cf' : 'General Information',
	'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' : 'Group Membership',
	'ffa6f046-ca4b-4feb-b40d-04dfee722543' : 'MS-TS-GatewayAccess',
	'77b5b886-944a-11d1-aebd-0000f80367c1' : 'Personal Information',
	'91e647de-d96f-4b70-9557-d63ff4f3ccd8' : 'Private Information',
	'e48d0154-bcf8-11d1-8702-00c04fb96050' : 'Public Information',
	'037088f8-0ae1-11d2-b422-00a0c968f939' : 'Remote Access Information',
	'5805bc62-bdc9-4428-a5e2-856a0f4c185e' : 'Terminal Server License Server',
	'4c164200-20c0-11d0-a768-00aa006e0529' : 'Account Restrictions',
	'5f202010-79a5-11d0-9020-00c04fc2d4cf' : 'Logon Information',
	'e45795b3-9455-11d1-aebd-0000f80367c1' : 'Web Information',
}

ValidatedWrites = {
	'bf9679c0-0de6-11d0-a285-00aa003049e2' : 'Add/Remove self as member',
	'72e39547-7b18-11d1-adef-00c04fd8d5cd' : 'Validated write to DNS host name',
	'80863791-dbe9-4eb8-837e-7f0ab55d9ac7' : 'Validated write to MS DS Additional DNS Host Name',
	'd31a8757-2447-4545-8081-3bb610cacbf2' : 'Validated write to MS DS behavior version',
	'f3a64788-5306-11d1-a9c5-0000f80367c1' : 'Validated write to service principal name',
}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEType(enum.Enum):	
	ACCESS_ALLOWED_ACE_TYPE = 0x00
	ACCESS_DENIED_ACE_TYPE = 0x01
	SYSTEM_AUDIT_ACE_TYPE = 0x02
	SYSTEM_ALARM_ACE_TYPE = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10 
	SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE =0x13

class AceFlags(enum.IntFlag):
	CONTAINER_INHERIT_ACE = 0x02
	FAILED_ACCESS_ACE_FLAG = 0x80
	INHERIT_ONLY_ACE = 0x08
	INHERITED_ACE = 0x10
	NO_PROPAGATE_INHERIT_ACE = 0x04
	OBJECT_INHERIT_ACE = 0x01
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40

# https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)

SDDL_ACE_TYPE_MAPS = {
	"A"  : ACEType.ACCESS_ALLOWED_ACE_TYPE,
	"D"  : ACEType.ACCESS_DENIED_ACE_TYPE,
	"OA" : ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
	"OD" : ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE,
	"AU" : ACEType.SYSTEM_AUDIT_ACE_TYPE,
	"AL" : ACEType.SYSTEM_ALARM_ACE_TYPE,
	"OU" : ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE,
	"OL" : ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE,
	"ML" : ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE,
	"XA" : ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, #Windows Vista and Windows Server 2003: Not available.
	"XD" : ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE, #Windows Vista and Windows Server 2003: Not available.
	"RA" : ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, #Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"SP" : ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, #Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"XU" : ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE, #Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"ZA" : ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, #Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
}
SDDL_ACE_TYPE_MAPS_INV = {v: k for k, v in SDDL_ACE_TYPE_MAPS.items()}

# http://www.coopware.in2.info/_ntfsacl_ht.htm
SDDL_ACE_FLAGS_MAPS = {
	"OI" : AceFlags.OBJECT_INHERIT_ACE, #This folder and files
	"CI" : AceFlags.CONTAINER_INHERIT_ACE, #This folder and subfolders
	"NP" : AceFlags.NO_PROPAGATE_INHERIT_ACE, #Apply these permissions 
	"IO" : AceFlags.INHERIT_ONLY_ACE,
	"ID" : AceFlags.INHERITED_ACE, #inherited
	"SA" : AceFlags.SUCCESSFUL_ACCESS_ACE_FLAG,
	"FA" : AceFlags.FAILED_ACCESS_ACE_FLAG,
}
SDDL_ACE_FLAGS_MAPS_INV = {v: k for k, v in SDDL_ACE_FLAGS_MAPS.items()}
	

def mask_to_str(mask, sd_object_type = None):
	if sd_object_type is None:
		return hex(mask)
	if sd_object_type == SE_OBJECT_TYPE.SE_FILE_OBJECT:
		return str(FILE_ACCESS_MASK(mask))
	elif sd_object_type == SE_OBJECT_TYPE.SE_SERVICE:
		return str(SERVICE_ACCESS_MASK(mask))
	elif sd_object_type == SE_OBJECT_TYPE.SE_REGISTRY_KEY:
		return str(REGISTRY_ACCESS_MASK(mask))
	else:
		return hex(mask)

def aceflags_to_sddl(flags):
	t = ''
	for k in SDDL_ACE_FLAGS_MAPS_INV:
		if k in flags:
			t += SDDL_ACE_FLAGS_MAPS_INV[k]
	return t

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
well_known_accessmasks = {
	"GR" : 0x80000000,
	"GW" : 0x40000000,
	"GX" : 0x20000000, #GE?
	"GA" : 0x10000000,
	"RC" : 0x00020000,
	"SD" : 0x00010000, # Delete
	"WD" : 0x00040000, # Modify Permissions
	"WO" : 0x00080000, # Modify Owner
	"RP" : 0x00000010, # Read All Properties 	
	"WP" : 0x00000020, # Write All Properties
	"CC" : 0x00000001, # Create All Child Objects
	"DC" : 0x00000002, # Delete All Child Objects
	"LC" : 0x00000004, # List Contents
	"SW" : 0x00000008, # All Validated Writes
	"LO" : 0x00000080, # List Object
	"DT" : 0x00000040, # Delete Subtree
	"CR" : 0x00000100, # All Extended Rights
	"FA" : 0x001f01ff, # File all
	"FX" : 0x001200A0, # File execute
	"FW" : 0x00120116,
	"FR" : 0x00120089,
	"KA" : 0x000f003f, # KEY ALL ACCESS 	 	
	"KR" : 0x00020019, # KEY READ
	"KX" : 0x00020019, # KEY EXECUTE
	"KW" : 0x00020006, # KEY WRITE
}
well_known_accessmasks_inv = {v: k for k, v in well_known_accessmasks.items()}
def accessmask_to_sddl(mask, sd_object_type):
	if mask in well_known_accessmasks_inv:
		return well_known_accessmasks_inv[mask]
	else:
		return hex(mask) 

def sddl_to_accessmask(mask_str):
	if mask_str in well_known_accessmasks:
		return well_known_accessmasks[mask_str]
	else:
		return int(mask_str, 16)

class ACE:
	def __init__(self):
		pass

	@staticmethod
	def from_bytes(data, sd_object_type = None):
		return ACE.from_buffer(io.BytesIO(data), sd_object_type)

	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		hdr = ACEHeader.pre_parse(buff)
		obj = acetype2ace.get(hdr.AceType)
		if not obj:
			raise Exception('ACE type %s not implemented!' % hdr.AceType)
		return obj.from_buffer(io.BytesIO(buff.read(hdr.AceSize)), sd_object_type)

	def to_buffer(self, buff):
		pass

	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_sddl(self, sd_object_type = None):
		pass
	
	@staticmethod
	def from_sddl(sddl:str, object_type = None, domain_sid = None):

		if sddl.startswith('('):
			sddl = sddl[1:]
		if sddl.endswith(')'):
			sddl = sddl[:-1]
		
		ace_type, ace_flags_str, rights, object_guid, inherit_object_guid, account_sid = sddl.split(';')

		ace_type = SDDL_ACE_TYPE_MAPS[ace_type]
		ace_flags = 0
		for i in range(0, len(ace_flags_str), 2):
			ace_flags |= SDDL_ACE_FLAGS_MAPS[ace_flags_str[i:i+2]]
		
		ace = acetype2ace[ace_type]()
		ace.AceFlags = AceFlags(ace_flags)
		ace.Mask = sddl_to_accessmask(rights)
		ace.Flags = 0
		ace.Sid = SID.from_sddl(account_sid, domain_sid = domain_sid)
		ace.sd_object_type = object_type

		if object_guid != '':
			ace.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
			ace.ObjectType = GUID.from_string(object_guid)
		if inherit_object_guid != '':
			ace.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT
			ace.InheritedObjectType = GUID.from_string(inherit_object_guid)

		return ace

	@staticmethod
	def add_padding(x):
		if (4 + len(x)) % 4 != 0:
			x += b'\x00' * ((4 + len(x)) % 4)
		return x

class ACCESS_ALLOWED_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_ACE_TYPE
		self.AceFlags = None
		self.AceSize = 0
		self.Mask = None
		self.Sid = None
		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		ace = ACCESS_ALLOWED_ACE()
		ace.sd_object_type = SE_OBJECT_TYPE(sd_object_type) if sd_object_type else None
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			'',
			'', 
			self.Sid.to_sddl()  
		)

	def __str__(self):
		t = 'ACCESS_ALLOWED_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)		
		return t
		
class ACCESS_DENIED_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_DENIED_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
	
	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			'',
			'', 
			self.Sid.to_sddl()  
		)
	
	def __str__(self):
		t = 'ACCESS_DENIED_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)		
		return t
		
class SYSTEM_AUDIT_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_AUDIT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
	

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			'',
			'', 
			self.Sid.to_sddl()  
		)
	
	def __str__(self):
		t = 'SYSTEM_AUDIT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)		
		return t
		
class SYSTEM_ALARM_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.SYSTEM_ALARM_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_ALARM_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			'',
			'', 
			self.Sid.to_sddl()  
		)
	
	def __str__(self):
		t = 'SYSTEM_ALARM_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)		
		return t
		
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ACE_OBJECT_PRESENCE(enum.IntFlag):
	NONE = 0x00000000 #Neither ObjectType nor InheritedObjectType are valid.
	ACE_OBJECT_TYPE_PRESENT = 0x00000001 #ObjectType is valid.
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 #InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.

class ACCESS_ALLOWED_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_ALLOWED_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			str(self.ObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
			str(self.InheritedObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '', 
			self.Sid.to_sddl()  
		)
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_DENIED_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_DENIED_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			str(self.ObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
			str(self.InheritedObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '', 
			self.Sid.to_sddl()  
		)
		
	def __str__(self):
		t = 'ACCESS_DENIED_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class SYSTEM_AUDIT_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None #must be bytes!
		

		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_OBJECT_ACE()
		ace.sd_object_type  = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
	
	#def to_sddl(self, sd_object_type = None):
	#	#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
	#	return '(%s;%s;%s;%s;%s;%s)' % ( 
	#		SDDL_ACE_TYPE_MAPS_INV[self.Header.AceType], 
	#		aceflags_to_sddl(self.Header.AceFlags), 
	#		accessmask_to_sddl(self.Mask, self.sd_object_type),
	#		self.ObjectType.to_bytes() if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
	#		self.InheritedObjectType.to_bytes() if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '', 
	#		self.Sid.to_sddl()  
	#	)
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_ALLOWED_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_ALLOWED_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_CALLBACK_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_DENIED_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_DENIED_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'ACCESS_DENIED_CALLBACK_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_DENIED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_DENIED_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'ACCESS_DENIED_CALLBACK_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_AUDIT_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_CALLBACK_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE\r\n'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_MANDATORY_LABEL_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_MANDATORY_LABEL_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class SYSTEM_RESOURCE_ATTRIBUTE_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.AttributeData = None #must be bytes for now. structure is TODO (see top of file)
		
		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_RESOURCE_ATTRIBUTE_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.AttributeData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.AttributeData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'SYSTEM_RESOURCE_ATTRIBUTE_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'AttributeData: %s \r\n' % self.AttributeData
		
		return t
		
class SYSTEM_SCOPED_POLICY_ID_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_SCOPED_POLICY_ID_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def __str__(self):
		t = 'SYSTEM_SCOPED_POLICY_ID_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)

		return t
		
acetype2ace = {
	ACEType.ACCESS_ALLOWED_ACE_TYPE : ACCESS_ALLOWED_ACE,
	ACEType.ACCESS_DENIED_ACE_TYPE : ACCESS_DENIED_ACE,
	ACEType.SYSTEM_AUDIT_ACE_TYPE : SYSTEM_AUDIT_ACE,
	ACEType.SYSTEM_ALARM_ACE_TYPE : SYSTEM_ALARM_ACE,
	ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE,
	ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE : ACCESS_DENIED_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE : SYSTEM_AUDIT_OBJECT_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE : ACCESS_DENIED_CALLBACK_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_DENIED_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE : SYSTEM_MANDATORY_LABEL_ACE,
	ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE : SYSTEM_RESOURCE_ATTRIBUTE_ACE,
	ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE : SYSTEM_SCOPED_POLICY_ID_ACE,
	}
"""
ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE : , # reserved
ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE : ,# reserved

"""

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEHeader:
	def __init__(self):
		self.AceType = None
		self.AceFlags = None
		self.AceSize = None

	def to_buffer(self, buff):
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		
	@staticmethod
	def from_bytes(data):
		return ACEHeader.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		return hdr
		
	@staticmethod
	def pre_parse(buff):
		pos = buff.tell()
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		buff.seek(pos,0)
		return hdr

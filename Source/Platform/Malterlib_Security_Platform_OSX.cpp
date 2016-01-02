// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>

#include <MacTypes.h>
#include <Security/Security.h>
#include <Mib/Process/ProcessLaunch>

/*
	Basic interface for storing secure passwords on a per-user, per-application basis.
*/

namespace 
{
	struct CSubSystem_Security_Platform_OSX_SecurePassword : public NMib::CSubSystem
	{
		NMib::NStr::CStr m_SecurePasswordLocation;
	};

	NMib::TCSubSystem<CSubSystem_Security_Platform_OSX_SecurePassword, NMib::ESubSystemDestruction_BeforeMemoryManager> g_SubSystem_Security_Platform_OSX_SecurePassword = {DAggregateInit};
	
	static NMib::NSys::ESecurePassword fg_SecurePassword_Decode_OSStatus(OSStatus _Status)
	{
		switch(_Status)
		{
			case errSecDuplicateItem:
				return NMib::NSys::ESecurePassword_Duplicate;

			case errSecDataTooLarge:
				return NMib::NSys::ESecurePassword_TooLarge;

			case errSecAuthFailed:
				return NMib::NSys::ESecurePassword_AuthFailed;

			case errSecItemNotFound:
				return NMib::NSys::ESecurePassword_NotFound;

			case noErr:
				return NMib::NSys::ESecurePassword_OK;

			default:
				return NMib::NSys::ESecurePassword_Failure;
		}			
	}
}


NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_SetLocation(NMib::NStr::CStr const& _Location)
{
	g_SubSystem_Security_Platform_OSX_SecurePassword->m_SecurePasswordLocation = _Location;

	return ESecurePassword_OK;
}

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Store(NMib::NStr::CStr const& _Key, NMib::NStr::CStrSecure const& _Password)
{			
	auto &SubSystem = *g_SubSystem_Security_Platform_OSX_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

	NMib::NStr::CStr Key = _Key;

	NMib::NStr::CStrSecure Password = _Password;

	OSStatus Status;

	Status = SecKeychainAddGenericPassword (
			NULL			// Default keychain
		,	SubSystem.m_SecurePasswordLocation.f_GetLen()
		,	SubSystem.m_SecurePasswordLocation.f_GetStr()
		,	Key.f_GetLen()	// Account name len
		,	Key.f_GetStr()	// Account name
		,	Password.f_GetLen() // Password len.
		,	Password.f_GetStr()	// Password
		,	NULL 			// the item reference
	);

	if (Status == errSecDuplicateItem)
	{ // Already exists, try changing the existing entry.

		SecKeychainItemRef ItemRef = nullptr;
		void* pExistingPassword = nullptr;
		UInt32 nExistingPasswordBytes = 0;

		Status = SecKeychainFindGenericPassword (
				nullptr			// Default keychain
			,	SubSystem.m_SecurePasswordLocation.f_GetLen()
			,	SubSystem.m_SecurePasswordLocation.f_GetStr()
			,	Key.f_GetLen()	// Account name len
			,	Key.f_GetStr()	// Account name
			,	&nExistingPasswordBytes 				// Password len.
			,	&pExistingPassword			// Password
			,	&ItemRef 		// the item reference
		);

		if (Status == noErr)
		{
			bint bPasswordEqual = Password == (NMib::NStr::CStrSecure::CChar const*)pExistingPassword;

			NMem::fg_ObjectSet((uint8*)pExistingPassword, 0, nExistingPasswordBytes);

			SecKeychainItemFreeContent(NULL, pExistingPassword);

			if (bPasswordEqual)
				return ESecurePassword_OK; // Password is already correct.

			Status = SecKeychainItemModifyAttributesAndData(
							ItemRef
						,	nullptr
						,	Password.f_GetLen()
						,	Password.f_GetStr()
					);

			CFRelease(ItemRef);

			ESecurePassword Ret = fg_SecurePassword_Decode_OSStatus(Status);
			if (Ret == ESecurePassword_Failure)
				DMibLog(Error, "NSys::fg_SecurePassword_Store - SecKeychainItemModifyContent failed with {}", (int)Status);
			return Ret;
		}
		else
		{
			// May be required to get string version of error here in the future.
			ESecurePassword Ret = fg_SecurePassword_Decode_OSStatus(Status);
			if (Ret == ESecurePassword_Failure)
				DMibLog(Error, "NSys::fg_SecurePassword_Store - SecKeychainFindGenericPassword failed with {}", (int)Status);
			return Ret;
		}

	}

	// May be required to get string version of error here in the future.
	return fg_SecurePassword_Decode_OSStatus(Status);
}

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Remove(NMib::NStr::CStr const& _Key)
{
	auto &SubSystem = *g_SubSystem_Security_Platform_OSX_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

	NMib::NStr::CStr Key = _Key;

	OSStatus Status;
	SecKeychainItemRef ItemRef = nullptr;

	Status = SecKeychainFindGenericPassword (
			nullptr			// Default keychain
		,	SubSystem.m_SecurePasswordLocation.f_GetLen()
		,	SubSystem.m_SecurePasswordLocation.f_GetStr()
		,	Key.f_GetLen()	// Account name len
		,	Key.f_GetStr()	// Account name
		,	0 				// Password len.
		,	nullptr			// Password
		,	&ItemRef 		// the item reference
	);

	if (Status == noErr)
	{
		Status = SecKeychainItemDelete(ItemRef);

		CFRelease(ItemRef);

		return fg_SecurePassword_Decode_OSStatus(Status);
	}
	else
	{
		// May be required to get string version of error here in the future.
		ESecurePassword Ret = fg_SecurePassword_Decode_OSStatus(Status);
		if (Ret == ESecurePassword_Failure)
			DMibLog(Error, "NSys::fg_SecurePassword_Remove - SecKeychainFindGenericPassword failed with {}", (int)Status);
		return Ret;
	}
}

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Get(NMib::NStr::CStr const& _Key, NMib::NStr::CStrSecure& _oPassword)
{
	auto &SubSystem = *g_SubSystem_Security_Platform_OSX_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

//			DMibLog(Error, "NSys::fg_SecurePassword_Get - Looking for {}", _Key);

	NMib::NStr::CStr Key = _Key;

	void* pPassword = nullptr;
	UInt32 nPasswordBytes = 0;

	OSStatus Status;
	SecKeychainItemRef ItemRef = nullptr;

	Status = SecKeychainFindGenericPassword (
			nullptr			// Default keychain
		,	SubSystem.m_SecurePasswordLocation.f_GetLen()
		,	SubSystem.m_SecurePasswordLocation.f_GetStr()
		,	Key.f_GetLen()	// Account name len
		,	Key.f_GetStr()	// Account name
		,	&nPasswordBytes // Password len.
		,	&pPassword		// Password
		,	&ItemRef 			// the item reference
	);

	if (Status == noErr)
	{
		_oPassword = NMib::NStr::CStrSecure( (NMib::NStr::CStrSecure::CChar*)pPassword, nPasswordBytes);

		NMem::fg_ObjectSet((uint8*)pPassword, 0, nPasswordBytes);

		SecKeychainItemFreeContent(NULL, pPassword);

		CFRelease(ItemRef);

		return ESecurePassword_OK;
	}
	else
	{
		// May be required to get string version of error here in the future.
		ESecurePassword Ret = fg_SecurePassword_Decode_OSStatus(Status);
		if (Ret == ESecurePassword_Failure)
			DMibLog(Error, "NSys::fg_SecurePassword_Get - SecKeychainFindGenericPassword failed with {}", (int)Status);
		return Ret;
	}

}

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Exists(NMib::NStr::CStr const& _Key)
{
	auto &SubSystem = *g_SubSystem_Security_Platform_OSX_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

//			DMibLog(Error, "NSys::fg_SecurePassword_Exists - Looking for {}", _Key);
	
	NMib::NStr::CStr Key = _Key;

	OSStatus Status;
	SecKeychainItemRef ItemRef = nullptr;

	Status = SecKeychainFindGenericPassword (
			nullptr			// Default keychain
		,	SubSystem.m_SecurePasswordLocation.f_GetLen()
		,	SubSystem.m_SecurePasswordLocation.f_GetStr()
		,	Key.f_GetLen()	// Account name len
		,	Key.f_GetStr()	// Account name
		,	0 				// Password len.
		,	nullptr			// Password
		,	&ItemRef		// the item reference
	);

	if (Status == noErr)
	{
		CFRelease(ItemRef);
		return ESecurePassword_OK;
	}
	else
	{
		// May be required to get string version of error here in the future.
		ESecurePassword Ret = fg_SecurePassword_Decode_OSStatus(Status);
		if (Ret == ESecurePassword_Failure)
			DMibLog(Error, "NSys::fg_SecurePassword_Exists - SecKeychainFindGenericPassword failed with {}", (int)Status);
		return Ret;
	}
}

bool NMib::NSys::fg_SecurePassword_Supported()
{
	return true;
}


/*
ESecurePassword NMib::NSys::fg_SecurePassword_Enum(NContainer::TCVector<CStr> & _oKeys)
{
	CStr ProgramName = fg_GetSys()->f_GetProgramName();

	OSStatus Status;

	SecKeychainAttributeList* pMatchAttribs;

	SecKeychainAttribute lAttribs[1];

	lAttribs[0].tag = kSecServiceItemAttr;
	lAttribs[0].data = ProgramName.f_GetStr();
	lAttribs[0].length = ProgramName.f_GetLen();

	SecKeychainAttributeList MatchAttribs = {1, lAttribs};

	SecKeychainSearchRef pSearch = nullptr;
	SecKeychainItemRef pItem = nullptr;

	auto Cleanup = fg_OnScopeExit(
			[&]()
			{
				if (pSearch)
					CFRelease(pSearch);
				if (pItem)
					CFRelease(pItem);
			}
		);

	Status = SecKeychainSearchCreateFromAttributes(
			NULL 
		,	kSecGenericPasswordItemClass
		,	MatchAttribs
		,	pSearch
		);

	if (Status != errSecSuccess)
	{
		return fg_SecurePassword_Decode_OSStatus(Status);
	}

	while (SecKeychainSearchCopyNext(pSearch, pItem) == errSecSuccess)
	{

		CFRelease(pItem);
		pItem = nullptr;
	}

}
*/
namespace
{
	NMib::NStr::CStr fg_UserManagement_CreateParameterString(NMib::NContainer::TCVector<NMib::NStr::CStr> const &_Parameters)
	{
		NMib::NStr::CStr Result;
		
		auto iParam = _Parameters.f_GetIterator();
		while (iParam)
		{
			fg_AddStrSepEscaped(Result, *iParam, ' ');
			++iParam;
		}
		
		return Result;
	}

	static int fg_GetHighestSecondColumnValue(NMib::NStr::CStr &_Data)
	{
		int Value = 0;
		while (!_Data.f_IsEmpty())
		{
			int NewLinePos = _Data.f_FindReverse("\n");
			if (NewLinePos == -1)
				break;
			_Data = _Data.f_Left(NewLinePos);
			int SpacePos = _Data.f_FindReverse(" ");
			NMib::NStr::CStr ValueString = _Data.f_Right(_Data.f_GetLen() - SpacePos - 1);
			int NewValue = ValueString.f_ToInt();
			if (NewValue > Value && NewValue < 500)
				Value = NewValue;
		}
		
		return Value;
	}
}

extern "C" uint32_t gL1CacheEnabled;

namespace
{
	void fg_UserManagement_ClearGroupCache()
	{
		// This disables caching of group entries
		gL1CacheEnabled = 0;
	}	

	void fg_UserManagement_ClearUserCache()
	{
		// This disables caching of password entries
		gL1CacheEnabled = 0;
	}
}

void NMib::NSys::fg_UserManagement_CreateGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr &_ReturnGID)
{
	
	int PrimaryGroupID = -1;

	{
		NMib::NStr::CStr StdOut;
		NMib::NStr::CStr StdErr;
		uint32 ExitCode;
		NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/bin/dscl", NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-read", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName, "PrimaryGroupID"), StdOut, StdErr, ExitCode);
		(NMib::NStr::CStr::CParse("PrimaryGroupID: {}") >> PrimaryGroupID).f_Parse(StdOut);
		if (PrimaryGroupID != -1)
			DMibError(NMib::NStr::CStr::CFormat("Group already exists: {}") << _GroupName);
	}			

	int GID;
	{
		NMib::NStr::CStr StdOut;
		NMib::NStr::CStr StdErr;
		uint32 ExitCode;
		if 
			(
				!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/bin/dscl", NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-list", "/Groups", "PrimaryGroupID"), StdOut, StdErr, ExitCode)
				|| ExitCode != 0
			)
		{
			DMibError(NMib::NStr::CStr::CFormat("Failed to list group: {}") << StdErr);
		}
		
		GID = fg_GetHighestSecondColumnValue(StdOut) + 1;
	}
	
	auto fl_dsclCall
		= [&](NContainer::TCVector<NMib::NStr::CStr> const &_Command)
		{
			NMib::NStr::CStr StdOut;
			NMib::NStr::CStr StdErr;
			uint32 ExitCode;
			if (!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/bin/dscl", _Command, StdOut, StdErr, ExitCode) || ExitCode != 0)
				DMibError(NMib::NStr::CStr::CFormat("Error when creating group command: /usr/bin/dscl {} : {}") << fg_UserManagement_CreateParameterString(_Command) << StdErr);
		}
	;
	
	fl_dsclCall(NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName));
	fl_dsclCall(NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName, "PrimaryGroupID", NMib::NStr::CStr::fs_ToStr(GID)));
	fl_dsclCall(NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName,"Password", "\\*"));

	_ReturnGID = NMib::NStr::CStr::fs_ToStr(GID);
	fg_UserManagement_ClearGroupCache();
}

void NMib::NSys::fg_UserManagement_DeleteGroup(NMib::NStr::CStr const &_GroupName)
{
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	
	uint32 ExitCode;

	if
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/bin/dscl", NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-delete", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName), StdOut, StdErr, ExitCode)
			|| ExitCode != 0
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Failed to delete group: {}") << StdErr);
	}
	fg_UserManagement_ClearGroupCache();
}

void NMib::NSys::fg_UserManagement_CreateUser(
								  NMib::NStr::CStr const &_InGroupName,
								  NMib::NStr::CStr const &_UserName,
								  NMib::NStr::CStr const &_Password,
								  NMib::NStr::CStr const &_FullName,
								  NMib::NStr::CStr const &_HomeDirectory,
								  NMib::NStr::CStr &_ReturnUID)
{
	int PrimaryGroupID = -1;

	{
		NMib::NStr::CStr StdOut;
		NMib::NStr::CStr StdErr;
		uint32 ExitCode;
		if 
			(
				!NMib::NProcess::CProcessLaunch::fs_LaunchBlock
				(
					"/usr/bin/dscl"
					, NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-read", NMib::NStr::CStr::CFormat("/Groups/{0}") << _InGroupName, "PrimaryGroupID")
					, StdOut
					, StdErr
					, ExitCode
				)
			)
		{
		}
	
		(NMib::NStr::CStr::CParse("PrimaryGroupID: {}") >> PrimaryGroupID).f_Parse(StdOut);
		if (PrimaryGroupID == -1)
			DMibError(NMib::NStr::CStr::CFormat("Group does not exists: {} ({})") << _InGroupName << StdErr);
	}
	
	
	int UniqueID = -1;

	{
		NMib::NStr::CStr StdOut;
		NMib::NStr::CStr StdErr;
		uint32 ExitCode;
		if 
			(
				!NMib::NProcess::CProcessLaunch::fs_LaunchBlock
				(
					"/usr/bin/dscl"
					, NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-read", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "UniqueID")
					, StdOut
					, StdErr
					, ExitCode
				)
			)
		{
		}
	
		(NMib::NStr::CStr::CParse("UniqueID: {}") >> UniqueID).f_Parse(StdOut);
		if (UniqueID != -1)
			DMibError(NMib::NStr::CStr::CFormat("User already exist: {} ()") << _UserName << StdErr);
	}
	

	{
		NMib::NStr::CStr StdOut;
		NMib::NStr::CStr StdErr;
		uint32 ExitCode;
		if 
			(
				!NMib::NProcess::CProcessLaunch::fs_LaunchBlock
				(
					"/usr/bin/dscl"
					, NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-list", "/Users", "UniqueID")
					, StdOut
					, StdErr
					, ExitCode
				)
				|| ExitCode != 0
			)
		{
			DMibError(NMib::NStr::CStr::CFormat("Failed to list users: {}") << StdErr);
		}
		
		UniqueID = fg_GetHighestSecondColumnValue(StdOut) + 1;
		
		if (UniqueID >= 500 || UniqueID == 0)
			DMibError("No free user id found below 500");
		
	}
	
	auto fdsclCall
		= [&](NMib::NContainer::TCVector<NMib::NStr::CStr> const &_Command)
		{
			NMib::NStr::CStr StdOut;
			NMib::NStr::CStr StdErr;
			uint32 ExitCode;
			if 
				(
					!NMib::NProcess::CProcessLaunch::fs_LaunchBlock
					(
						"/usr/bin/dscl"
						, _Command
						, StdOut
						, StdErr
						, ExitCode
					)
					|| ExitCode != 0
				)
			{
				DMibError(NMib::NStr::CStr::CFormat("Error when creating user command {} : {}") << fg_UserManagement_CreateParameterString(_Command) << StdErr);
			}
		}
	;
	
	fdsclCall(NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName));
	fdsclCall(NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "UniqueID", NMib::NStr::CStr::fs_ToStr(UniqueID)));
	fdsclCall(NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "PrimaryGroupID", NMib::NStr::CStr::fs_ToStr(PrimaryGroupID)));
	fdsclCall(NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "UserShell", "/usr/bin/false"));
	fdsclCall(NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "NFSHomeDirectory", _HomeDirectory));
	fdsclCall(NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "RealName", _FullName));
	fdsclCall(NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "IsHidden", "1"));
	fdsclCall(NMib::NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "Password", "\\*"));

	_ReturnUID = NMib::NStr::CStr::fs_ToStr(UniqueID);
	fg_UserManagement_ClearUserCache();
}

void NMib::NSys::fg_UserManagement_DeleteUser(NMib::NStr::CStr const &_UserName)
{
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	uint32 ExitCode;

	if 
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock
			(
				"/usr/bin/dscl"
				, NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-delete", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName)
				, StdOut
				, StdErr
				, ExitCode
			)
			|| ExitCode != 0
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Failed to delete user: {}") << StdErr);
	}
	fg_UserManagement_ClearUserCache();
}

void NMib::NSys::fg_UserManagement_AddUserToGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	if (NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(_GroupName, _UserName))
		DMibError(NMib::NStr::CStr::CFormat("User {} does already exist in group {}") << _UserName << _GroupName);
	
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;

	uint32 ExitCode;

	if 
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock
			(
				"/usr/bin/dscl"
				, NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-append", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName, "GroupMembership", _UserName)
				, StdOut
				, StdErr
				, ExitCode
			)
			|| ExitCode != 0
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Failed to add user {} to group {}: {}") << _UserName << _GroupName << StdErr);
	}
	fg_UserManagement_ClearUserCache();
	fg_UserManagement_ClearGroupCache();
}

void NMib::NSys::fg_UserManagement_RemoveUserFromGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	if (!NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(_GroupName, _UserName))
		DMibError(NMib::NStr::CStr::CFormat("User {} does not exist in group {}") << _UserName << _GroupName);
	
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	uint32 ExitCode;

	if 
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock
			(
				"/usr/bin/dscl"
				, NContainer::fg_CreateVector<NMib::NStr::CStr>(".", "-delete", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName, "GroupMembership", _UserName)
				, StdOut
				, StdErr
				, ExitCode
			)
			|| ExitCode != 0
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Failed to delete user {} from group {}: {}") << _UserName << _GroupName << StdErr);
	}
	fg_UserManagement_ClearUserCache();
	fg_UserManagement_ClearGroupCache();
}

bint NMib::NSys::fg_UserManagement_IsValidName(NMib::NStr::CStr const &_Name)
{
	return _Name.f_FindChar(' ') < 0;
}


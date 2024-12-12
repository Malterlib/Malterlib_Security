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
	struct CSubSystem_Security_Platform_MacOS_SecurePassword : public NMib::CSubSystem
	{
		NMib::NStr::CStr m_SecurePasswordLocation;
	};

	constinit NMib::TCSubSystem<CSubSystem_Security_Platform_MacOS_SecurePassword, NMib::ESubSystemDestruction_BeforeMemoryManager>
		g_SubSystem_Security_Platform_MacOS_SecurePassword = {DAggregateInit}
	;
	
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

	template <typename tf_FCheck>
	void fg_WaitForUpdate(tf_FCheck &&_fCheck)
	{
		NMib::NTime::CClock Clock{true};

		while (!_fCheck())
		{
			NMib::NSys::fg_Thread_SmallestSleep();
			if (Clock.f_GetTime() > 60.0)
				DMibError("Timed out waiting for user/group change to come into effect");
		}
	}
}


NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_SetLocation(NMib::NStr::CStr const& _Location)
{
	g_SubSystem_Security_Platform_MacOS_SecurePassword->m_SecurePasswordLocation = _Location;

	return ESecurePassword_OK;
}

bool NMib::NSys::fg_SecurePassword_IsLocked()
{
	return false;
}

#if DPlatformVersion >= 100100
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Store(NMib::NStr::CStr const& _Key, NMib::NStr::CStrSecure const& _Password)
{			
	auto &SubSystem = *g_SubSystem_Security_Platform_MacOS_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

	NMib::NStr::CStr Key = _Key;

	NMib::NStr::CStrSecure Password = _Password;

	OSStatus Status;

	Status = SecKeychainAddGenericPassword
		(
			NULL			// Default keychain
			, SubSystem.m_SecurePasswordLocation.f_GetLen()
			, SubSystem.m_SecurePasswordLocation.f_GetStr()
			, Key.f_GetLen()	// Account name len
			, Key.f_GetStr()	// Account name
			, Password.f_GetLen() // Password len.
			, Password.f_GetStr()	// Password
			, NULL			// the item reference
		)
	;

	if (Status == errSecDuplicateItem)
	{ // Already exists, try changing the existing entry.

		SecKeychainItemRef ItemRef = nullptr;
		void* pExistingPassword = nullptr;
		UInt32 nExistingPasswordBytes = 0;

		Status = SecKeychainFindGenericPassword
			(
				nullptr			// Default keychain
				, SubSystem.m_SecurePasswordLocation.f_GetLen()
				, SubSystem.m_SecurePasswordLocation.f_GetStr()
				, Key.f_GetLen()	// Account name len
				, Key.f_GetStr()	// Account name
				, &nExistingPasswordBytes				// Password len.
				, &pExistingPassword			// Password
				, &ItemRef		// the item reference
			)
		;

		if (Status == noErr)
		{
			NMib::NStr::CStrSecure ExistingPassword{(ch8 const *)pExistingPassword, nExistingPasswordBytes};
			bool bPasswordEqual = Password == ExistingPassword;

			NMemory::fg_ObjectSet((uint8*)pExistingPassword, 0, nExistingPasswordBytes);

			SecKeychainItemFreeContent(NULL, pExistingPassword);

			if (bPasswordEqual)
			{
				CFRelease(ItemRef);
				return ESecurePassword_OK; // Password is already correct.
			}

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
	auto &SubSystem = *g_SubSystem_Security_Platform_MacOS_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

	NMib::NStr::CStr Key = _Key;

	OSStatus Status;
	SecKeychainItemRef ItemRef = nullptr;

	Status = SecKeychainFindGenericPassword
		(
			nullptr			// Default keychain
			, SubSystem.m_SecurePasswordLocation.f_GetLen()
			, SubSystem.m_SecurePasswordLocation.f_GetStr()
			, Key.f_GetLen()	// Account name len
			, Key.f_GetStr()	// Account name
			, 0				// Password len.
			, nullptr			// Password
			, &ItemRef		// the item reference
		)
	;

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
	auto &SubSystem = *g_SubSystem_Security_Platform_MacOS_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

//			DMibLog(Error, "NSys::fg_SecurePassword_Get - Looking for {}", _Key);

	NMib::NStr::CStr Key = _Key;

	void* pPassword = nullptr;
	UInt32 nPasswordBytes = 0;

	OSStatus Status;
	SecKeychainItemRef ItemRef = nullptr;

	Status = SecKeychainFindGenericPassword
		(
			nullptr			// Default keychain
			, SubSystem.m_SecurePasswordLocation.f_GetLen()
			, SubSystem.m_SecurePasswordLocation.f_GetStr()
			, Key.f_GetLen()	// Account name len
			, Key.f_GetStr()	// Account name
			, &nPasswordBytes // Password len.
			, &pPassword		// Password
			, &ItemRef			// the item reference
		)
	;

	if (Status == noErr)
	{
		_oPassword = NMib::NStr::CStrSecure( (NMib::NStr::CStrSecure::CChar*)pPassword, nPasswordBytes);

		NMemory::fg_ObjectSet((uint8*)pPassword, 0, nPasswordBytes);

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
	auto &SubSystem = *g_SubSystem_Security_Platform_MacOS_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

//			DMibLog(Error, "NSys::fg_SecurePassword_Exists - Looking for {}", _Key);
	
	NMib::NStr::CStr Key = _Key;

	OSStatus Status;
	SecKeychainItemRef ItemRef = nullptr;

	Status = SecKeychainFindGenericPassword
		(
			nullptr			// Default keychain
			, SubSystem.m_SecurePasswordLocation.f_GetLen()
			, SubSystem.m_SecurePasswordLocation.f_GetStr()
			, Key.f_GetLen()	// Account name len
			, Key.f_GetStr()	// Account name
			, 0				// Password len.
			, nullptr			// Password
			, &ItemRef		// the item reference
		)
	;

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

#if DPlatformVersion > 100100
#pragma clang diagnostic pop
#endif

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

	auto Cleanup = fg_OnScopeExit
		(
			[&]()
			{
				if (pSearch)
					CFRelease(pSearch);
				if (pItem)
					CFRelease(pItem);
			}
		);

	Status = SecKeychainSearchCreateFromAttributes
		(
			NULL 
			, kSecGenericPasswordItemClass
			, MatchAttribs
			, pSearch
		)
	;

	if (Status != errSecSuccess)
		return fg_SecurePassword_Decode_OSStatus(Status);

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

	NMib::NContainer::TCSet<int> fg_GetCurrentIDs(NMib::NStr::CStr &_Data)
	{
		NMib::NContainer::TCSet<int> IDs;

		while (!_Data.f_IsEmpty())
		{
			int NewLinePos = _Data.f_FindReverse("\n");
			if (NewLinePos == -1)
				break;
			_Data = _Data.f_Left(NewLinePos);
			int SpacePos = _Data.f_FindReverse(" ");
			NMib::NStr::CStr ValueString = _Data.f_Right(_Data.f_GetLen() - SpacePos - 1);
			int NewValue = ValueString.f_ToInt(int(-1));
			if (NewValue >= 0)
				IDs[NewValue];
		}
		
		return IDs;
	}

	int fg_GetFreeID(NMib::NContainer::TCSet<int> const &_CurrentIDs)
	{
		if (NMib::CSystem::ms_PlatformVersion < 10'10'00)
		{
			for (int FreeID = 499; FreeID >= 0; --FreeID)
			{
				if (!_CurrentIDs.f_FindEqual(FreeID))
					return FreeID;
			}
			DMibError("No free ID found below 500");
		}
		else
		{
			for (int FreeID = 501; FreeID < 8192; ++FreeID)
			{
				if (!_CurrentIDs.f_FindEqual(FreeID))
					return FreeID;
			}

			DMibError("No free ID found");
		}
		return -1;
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
		NMib::NStr::CStr FileLockName = NMib::NFile::CFile::fs_GetRawTemporaryDirectory() / "dscl-gid.lock"; // Prevent race conditions
		NMib::NFile::CLockFile LockFile(FileLockName);
		LockFile.f_Lock();

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

			auto CurrentIDs = fg_GetCurrentIDs(StdOut);
			GID = fg_GetFreeID(CurrentIDs);
		}

		auto fCallDscl
			= [&](NContainer::TCVector<NMib::NStr::CStr> const &_Command)
			{
				NMib::NStr::CStr StdOut;
				NMib::NStr::CStr StdErr;
				uint32 ExitCode;
				if (!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/bin/dscl", _Command, StdOut, StdErr, ExitCode) || ExitCode != 0)
					DMibError(NMib::NStr::CStr::CFormat("Error when creating group command: /usr/bin/dscl {} : {}") << fg_UserManagement_CreateParameterString(_Command) << StdErr);
			}
		;

		fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName});
		fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName, "PrimaryGroupID", NMib::NStr::CStr::fs_ToStr(GID)});
		fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Groups/{0}") << _GroupName, "Password", "\\*"});
	}

	_ReturnGID = NMib::NStr::CStr::fs_ToStr(GID);
	fg_UserManagement_ClearGroupCache();

	fg_WaitForUpdate
		(
			[&]
			{
				NMib::NStr::CStr ID;
				return NMib::NSys::fg_UserManagement_GroupExists(_GroupName, ID);
			}
		)
	;
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

	fg_WaitForUpdate
		(
			[&]
			{
				NMib::NStr::CStr ID;
				return !NMib::NSys::fg_UserManagement_GroupExists(_GroupName, ID);
			}
		)
	;
}

NMib::NStr::CStr NMib::NSys::fg_UserManagement_MakeValidUserName(NMib::NStr::CStr const &_UserName)
{
	// We limit to 32 characters here, because that is what tar supports
	if (_UserName.f_GetLen() <= 32)
		return _UserName;

	NMib::NCryptography::CHash_SHA256 Hash;
	Hash.f_AddData(_UserName.f_GetStr(), _UserName.f_GetLen());

	auto Digest = Hash.f_GetDigest();

	return _UserName.f_Left(24) + Digest.f_GetString().f_Left(8);
}

NMib::NStr::CStr NMib::NSys::fg_UserManagement_MakeValidGroupName(NMib::NStr::CStr const &_GroupName)
{
	return fg_UserManagement_MakeValidUserName(_GroupName);
}

void NMib::NSys::fg_UserManagement_SetUserPassword
	(
		NMib::NStr::CStr const &_UserName
		, NMib::NStr::CStrSecure const &_Password
	)
{
	DMibError("Not implemented");
}

void NMib::NSys::fg_UserManagement_CreateUser
	(
		NMib::NStr::CStr const &_InGroupName
		, NMib::NStr::CStr const &_UserName
		, NMib::NStr::CStrSecure const &_Password
		, NMib::NStr::CStr const &_FullName
		, NMib::NStr::CStr const &_HomeDirectory
		, NMib::NStr::CStr &_ReturnUID
		, EUserManagementCreateUserFlag _Flags
	)
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

	mint nRetry = 0;
l_Retry:
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
		
		auto CurrentIDs = fg_GetCurrentIDs(StdOut);
		UniqueID = fg_GetFreeID(CurrentIDs);
	}
	
	auto fCallDscl
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
	
	fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName});

	try
	{
		fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "UniqueID", NMib::NStr::CStr::fs_ToStr(UniqueID)});
	}
	catch (NException::CException const &_Exception)
	{
		if (nRetry < 16 && _Exception.f_GetErrorStr().f_Find("eDSRecordAlreadyExists") >= 0)
		{
			++nRetry;
			goto l_Retry; // Race condition
		}
		throw;
	}

	fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "PrimaryGroupID", NMib::NStr::CStr::fs_ToStr(PrimaryGroupID)});
	fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "UserShell", (_Flags & EUserManagementCreateUserFlag_ShellAccess) ? "/bin/bash" : "/bin/false"});
	fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "NFSHomeDirectory", _HomeDirectory});
	fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "RealName", _FullName});
	fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "IsHidden", "1"});
	fCallDscl({".", "-create", NMib::NStr::CStr::CFormat("/Users/{0}") << _UserName, "Password", "\\*"});

	_ReturnUID = NMib::NStr::CStr::fs_ToStr(UniqueID);
	fg_UserManagement_ClearUserCache();

	fg_WaitForUpdate
		(
			[&]
			{
				NMib::NStr::CStr ID;
				return NMib::NSys::fg_UserManagement_UserExists(_UserName, ID);
			}
		)
	;
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

	fg_WaitForUpdate
		(
			[&]
			{
				NMib::NStr::CStr ID;
				return !NMib::NSys::fg_UserManagement_UserExists(_UserName, ID);
			}
		)
	;
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


	fg_WaitForUpdate
		(
			[&]
			{
				return NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(_GroupName, _UserName);
			}
		)
	;
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

	fg_WaitForUpdate
		(
			[&]
			{
				return !NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(_GroupName, _UserName);
			}
		)
	;
}

bool NMib::NSys::fg_UserManagement_IsValidName(NMib::NStr::CStr const &_Name)
{
	return _Name.f_FindChar(' ') < 0;
}


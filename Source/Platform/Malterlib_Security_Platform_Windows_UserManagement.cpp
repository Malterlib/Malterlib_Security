// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Core/PlatformSpecific/WindowsError>
#include <Mib/Core/PlatformSpecific/WindowsString>
#include <Mib/Core/PlatformSpecific/WindowsFilePath>
#include <Mib/Cryptography/Hashes/SHA>

#include <Windows.h>
#include <lmcons.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <lmapibuf.h>
#include <LsaLookup.h>
#include <Ntsecapi.h>

#pragma comment(lib, "netapi32.lib")

using namespace NMib;

NMib::NStr::CStr NMib::NSys::fg_UserManagement_MakeValidUserName(NMib::NStr::CStr const &_UserName)
{
	if (_UserName.f_GetLen() <= 20)
		return _UserName;

	NMib::NCryptography::CHash_SHA256 Hash;
	Hash.f_AddData(_UserName.f_GetStr(), _UserName.f_GetLen());

	auto Digest = Hash.f_GetDigest();

	return _UserName.f_Left(12) + Digest.f_GetString().f_Left(8);
}

NMib::NStr::CStr NMib::NSys::fg_UserManagement_MakeValidGroupName(NMib::NStr::CStr const &_GroupName)
{
	// We limit to 32 characters here, because that is what tar supports
	if (_GroupName.f_GetLen() <= 32)
		return _GroupName;

	NMib::NCryptography::CHash_SHA256 Hash;
	Hash.f_AddData(_GroupName.f_GetStr(), _GroupName.f_GetLen());

	auto Digest = Hash.f_GetDigest();

	return _GroupName.f_Left(24) + Digest.f_GetString().f_Left(8);
}

void NMib::NSys::fg_UserManagement_CreateGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr &o_ReturnGID)
{
	LOCALGROUP_INFO_0 GroupInfo;
	NMemory::fg_MemClear(GroupInfo);

	NMib::NStr::CWStr GroupName = NMib::NStr::NPlatform::fg_StrToWindows(_GroupName);
	GroupInfo.lgrpi0_name = GroupName.f_GetStrUniqueWritable();

	NET_API_STATUS Status = NetLocalGroupAdd(nullptr, 0, (uint8 *)&GroupInfo, nullptr);

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetLocalGroupAdd({}): {}") << _GroupName << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	o_ReturnGID = _GroupName;
}

void NMib::NSys::fg_UserManagement_DeleteGroup(NMib::NStr::CStr const &_GroupName)
{
	NMib::NStr::CWStr GroupName = NMib::NStr::NPlatform::fg_StrToWindows(_GroupName);
	NET_API_STATUS Status = NetLocalGroupDel(nullptr, GroupName.f_GetStr());

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetLocalGroupDel: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());
}

void NMib::NSys::fg_UserManagement_SetUserPassword
	(
		NMib::NStr::CStr const &_UserName
		, NMib::NStr::CStrSecure const &_Password
	)
{
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);
	NMib::NStr::CWStr Password = NMib::NStr::NPlatform::fg_StrToWindows<NMib::NStr::CWStrSecure>(_Password);
	
	USER_INFO_1003 PasswordInfo;
	NMemory::fg_MemClear(PasswordInfo);
	PasswordInfo.usri1003_password = Password.f_GetStrUniqueWritable();

	NET_API_STATUS Status = NetUserSetInfo(nullptr, UserName.f_GetStr(), 1003, (uint8 *)&PasswordInfo, nullptr);
	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserSetInfo(Set password): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());
}

void NMib::NSys::fg_UserManagement_CreateUser
	(
		NMib::NStr::CStr const &_InGroupName
		, NMib::NStr::CStr const &_UserName
		, NMib::NStr::CStrSecure const &_Password
		, NMib::NStr::CStr const &_FullName
		, NMib::NStr::CStr const &_HomeDirectory
		, NMib::NStr::CStr &o_ReturnUID
	 	, EUserManagementCreateUserFlag _Flags
	)
{
	USER_INFO_1 UserInfo;
	NMemory::fg_MemClear(UserInfo);

	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);
	NMib::NStr::CWStr Password = NMib::NStr::NPlatform::fg_StrToWindows<NMib::NStr::CWStrSecure>(_Password);
	NMib::NStr::CWStr FullName = NMib::NStr::NPlatform::fg_StrToWindows(_FullName);

	UserInfo.usri1_name = UserName.f_GetStrUniqueWritable();
	UserInfo.usri1_password = Password.f_GetStrUniqueWritable();
	UserInfo.usri1_priv = USER_PRIV_USER;
	UserInfo.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

	uint32 ParmError = 0;
	NET_API_STATUS Status = NetUserAdd(nullptr, 1, (uint8 *)&UserInfo, &ParmError);

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserAdd('{}'), param {}: {}") << _UserName << ParmError << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	USER_INFO_1011 FullNameInfo;
	NMemory::fg_MemClear(FullNameInfo);
	FullNameInfo.usri1011_full_name = FullName.f_GetStrUniqueWritable();

	Status = NetUserSetInfo(nullptr, UserName.f_GetStr(), 1011, (uint8 *)&FullNameInfo, nullptr);
	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserSetInfo(Set full name): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	USER_INFO_1013 ParamsInfo;
	NMemory::fg_MemClear(ParamsInfo);
	NMib::NStr::CWStr Params = NMib::NStr::NPlatform::fg_StrToWindows(NMib::NStr::fg_Format("MalterlibUserGroup: {}", _InGroupName));
	ParamsInfo.usri1013_parms = Params.f_GetStrUniqueWritable();

	Status = NetUserSetInfo(nullptr, UserName.f_GetStr(), 1013, (uint8 *)&ParamsInfo, nullptr);
	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserSetInfo(Set params): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	if (_Flags & EUserManagementCreateUserFlag_SupportUILogin)
		fg_UserManagement_AddUserToGroup("Users", _UserName);

	if (!_InGroupName.f_IsEmpty())
		fg_UserManagement_AddUserToGroup(_InGroupName, _UserName);

	o_ReturnUID = _UserName;
}

void NMib::NSys::fg_UserManagement_DeleteUser(NMib::NStr::CStr const &_UserName)
{
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);

	NET_API_STATUS Status = NetUserDel(nullptr, UserName.f_GetStr());

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserDel: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());
}

void NMib::NSys::fg_UserManagement_AddUserToGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	NMib::NStr::CWStr GroupName = NMib::NStr::NPlatform::fg_StrToWindows(_GroupName);
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);

	LOCALGROUP_MEMBERS_INFO_3 Members;
	Members.lgrmi3_domainandname = UserName.f_GetStrUniqueWritable();

	NET_API_STATUS Status = NetLocalGroupAddMembers(nullptr, GroupName.f_GetStr(), 3, (uint8 *)&Members, 1);

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetLocalGroupAddMembers('{}', '{}'): {}") << _GroupName << _UserName << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());
}

void NMib::NSys::fg_UserManagement_RemoveUserFromGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	NMib::NStr::CWStr GroupName = NMib::NStr::NPlatform::fg_StrToWindows(_GroupName);
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);

	LOCALGROUP_MEMBERS_INFO_3 Members;
	Members.lgrmi3_domainandname = UserName.f_GetStrUniqueWritable();

	NET_API_STATUS Status = NetLocalGroupDelMembers(nullptr, GroupName.f_GetStr(), 3, (uint8 *)&Members, 1);

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetLocalGroupDelMembers('{}', '{}'): {}") << _GroupName << _UserName << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());
}

 bool NMib::NSys::fg_UserManagement_IsValidName(NMib::NStr::CStr const &_Name)
{
	if (_Name.f_FindChars("\"/\\[]:|<>+=,;?*") >= 0 || _Name.f_EndsWith("."))
		 return false;

	for (auto pParse = _Name.f_GetStr(); *pParse; ++pParse)
	{
		if (*pParse <= 31)
			return false;
	}

	return true;
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessRealUser()
{
	HANDLE ProcessToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &ProcessToken))
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from OpenProcessToken(Get process real user): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr()).f_GetStr());

	auto Cleanup = g_OnScopeExit > [&]
		{
			CloseHandle(ProcessToken);
		}
	;

	uint32 NeededLength = 0;
	GetTokenInformation(ProcessToken, TokenUser, nullptr, 0, &NeededLength);

	NContainer::CByteVector TokenData;
	if (!GetTokenInformation(ProcessToken, TokenUser, TokenData.f_GetArray(NeededLength), NeededLength, &NeededLength))
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from GetTokenInformation(Get process real user): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr()).f_GetStr());

	TOKEN_USER &TokenUserInfo = *((TOKEN_USER *)TokenData.f_GetArray());

	SID_NAME_USE AccountType;
	NMib::NStr::CWStr ReferencedDomainName;
	uint32 ReferencedDomainNameSize = 8192;

	NMib::NStr::CWStr UserName;
	uint32 UserNameSize = 8192;

	if (!LookupAccountSid(nullptr, TokenUserInfo.User.Sid, UserName.f_GetStr(8192 + 1), &UserNameSize, ReferencedDomainName.f_GetStr(8192+1), &ReferencedDomainNameSize, &AccountType))
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from LookupAccountSid(Get process real user): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr()).f_GetStr());

	using namespace ::NMib::NStr;
	if (ReferencedDomainName.f_IsEmpty())
		return UserName;
	else
		return "{}\\{}"_f << ReferencedDomainName << UserName;
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessRealGroup()
{
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(fg_UserManagement_GetProcessRealUser());

	NMib::NStr::CWStr DomainName;
	ch16 const *pDomainName = nullptr;
	if (UserName.f_FindChar('\\') >= 0)
	{
		auto Split = UserName.f_Split("\\");
		DomainName = Split[0];
		UserName = Split[1];
		pDomainName = DomainName.f_GetStr();
	}

	uint8 *pData = nullptr;
	NET_API_STATUS Status = NetUserGetInfo(pDomainName, UserName.f_GetStr(), 1013, &pData);

	auto Cleanup = g_OnScopeExit > [&]
		{
			if (pData)
				NetApiBufferFree(pData);
		}
	;

	if (Status == NERR_Success)
	{
		USER_INFO_1013 &UserInfo = *((USER_INFO_1013 *)pData);

		NMib::NStr::CStr Params;
		if (UserInfo.usri1013_parms)
			Params = NMib::NStr::CWStr(UserInfo.usri1013_parms);

		for (auto &Line : Params.f_SplitLine())
		{
			if (Line.f_StartsWith("MalterlibUserGroup: "))
				return Line.f_Extract(20);
		}
	}

	{
		HANDLE ProcessToken;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &ProcessToken))
			DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from OpenProcessToken(Get process real user): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr()).f_GetStr());

		auto Cleanup = g_OnScopeExit > [&]
			{
				CloseHandle(ProcessToken);
			}
		;

		uint32 NeededLength = 0;
		GetTokenInformation(ProcessToken, TokenPrimaryGroup, nullptr, 0, &NeededLength);

		NContainer::CByteVector TokenData;
		if (!GetTokenInformation(ProcessToken, TokenPrimaryGroup, TokenData.f_GetArray(NeededLength), NeededLength, &NeededLength))
			DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from GetTokenInformation(Get process real user): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr()).f_GetStr());

		TOKEN_PRIMARY_GROUP &TokenPrimaryInfo = *((TOKEN_PRIMARY_GROUP *)TokenData.f_GetArray());

		SID_NAME_USE AccountType;
		NMib::NStr::CWStr ReferencedDomainName;
		NMib::NStr::CWStr GroupName;

		uint32 ReferencedDomainNameSize = 8192;
		uint32 GroupNameSize = 8192;
		if (!LookupAccountSid(nullptr, TokenPrimaryInfo.PrimaryGroup, GroupName.f_GetStr(8192 + 1), &GroupNameSize, ReferencedDomainName.f_GetStr(8192+1), &ReferencedDomainNameSize, &AccountType))
			DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from LookupAccountSid(Get process real group): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr()).f_GetStr());

		using namespace ::NMib::NStr;
		if (ReferencedDomainName.f_IsEmpty())
			return GroupName;
		else
			return "{}\\{}"_f << ReferencedDomainName << GroupName;
	}
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessRealUserName()
{
	return fg_UserManagement_GetProcessRealUser();
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessRealGroupName()
{
	return fg_UserManagement_GetProcessRealGroup();
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessEffectiveUser()
{
	return fg_UserManagement_GetProcessRealUser();
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessEffectiveGroup()
{
	return fg_UserManagement_GetProcessRealGroup();
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessEffectiveUserName()
{
	return fg_UserManagement_GetProcessRealUserName();
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessEffectiveGroupName()
{
	return fg_UserManagement_GetProcessRealGroupName();
}


bool NSys::fg_UserManagement_GroupExists(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr &o_ReturnGID)
{
	NMib::NStr::CWStr GroupName = NMib::NStr::NPlatform::fg_StrToWindows(_GroupName);

	NMib::NStr::CWStr DomainName;
	ch16 const *pDomainName = nullptr;
	if (GroupName.f_FindChar('\\') >= 0)
	{
		auto Split = GroupName.f_Split("\\");
		DomainName = Split[0];
		GroupName = Split[1];
		pDomainName = DomainName.f_GetStr();
	}

	if (DomainName == "NT AUTHORITY")
		return true;

	uint8 *pData = nullptr;
	NET_API_STATUS Status = NetLocalGroupGetInfo(pDomainName, GroupName.f_GetStr(), 0, &pData);

	auto Cleanup = g_OnScopeExit > [&]
		{
			if (pData)
				NetApiBufferFree(pData);
		}
	;

	if (Status == NERR_GroupNotFound)
		return false;
	else if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetLocalGroupGetInfo({}): {}") << GroupName << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	o_ReturnGID = _GroupName;
	return true;
}

bool NSys::fg_UserManagement_UserExists(NMib::NStr::CStr const &_UserName, NMib::NStr::CStr &o_ReturnUID)
{
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);

	NMib::NStr::CWStr DomainName;
	ch16 const *pDomainName = nullptr;
	if (UserName.f_FindChar('\\') >= 0)
	{
		auto Split = UserName.f_Split("\\");
		DomainName = Split[0];
		UserName = Split[1];
		pDomainName = DomainName.f_GetStr();
	}

	if (DomainName == "NT AUTHORITY")
		return true;

	uint8 *pData = nullptr;
	NET_API_STATUS Status = NetUserGetInfo(pDomainName, UserName.f_GetStr(), 0, &pData);

	auto Cleanup = g_OnScopeExit > [&]
		{
			if (pData)
				NetApiBufferFree(pData);
		}
	;

	if (Status == NERR_UserNotFound)
		return false;
	else if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserGetInfo({}): {}") << UserName << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	o_ReturnUID = _UserName;
	return true;
}

NMib::NContainer::TCVector<NMib::NStr::CStr> NSys::fg_UserManagement_UserGetMemberOfGroups(NMib::NStr::CStr const &_UserName)
{
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);

	NMib::NStr::CWStr DomainName;
	ch16 const *pDomainName = nullptr;
	if (UserName.f_FindChar('\\') >= 0)
	{
		auto Split = UserName.f_Split("\\");
		DomainName = Split[0];
		UserName = Split[1];
		pDomainName = DomainName.f_GetStr();
	}

	if (DomainName == "NT AUTHORITY")
		pDomainName = nullptr;

	uint8 *pData = nullptr;
	uint32 EntriesRead = 0;
	uint32 TotalEntries = 0;
	NET_API_STATUS Status = ERROR_MORE_DATA;
	while (Status == ERROR_MORE_DATA)
		Status = NetUserGetLocalGroups(pDomainName, UserName.f_GetStr(), 0, LG_INCLUDE_INDIRECT, &pData, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries);

	auto Cleanup = g_OnScopeExit > [&]
		{
			if (pData)
				NetApiBufferFree(pData);
		}
	;

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserGetLocalGroups: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	LOCALGROUP_USERS_INFO_0 *pEntries = (LOCALGROUP_USERS_INFO_0 *)pData;

	NMib::NContainer::TCVector<NMib::NStr::CStr>  Return;
	for (mint i = 0; i < EntriesRead; ++i)
		Return.f_Insert(NMib::NStr::CWStr(pEntries[i].lgrui0_name));

	return Return;
}

bool NSys::fg_UserManagement_UserIsMemberOfGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	auto Groups = fg_UserManagement_UserGetMemberOfGroups(_UserName);

	for (auto &Group : Groups)
	{
		if (Group == _GroupName)
			return true;
	}

	return false;
}

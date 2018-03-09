// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Core/PlatformSpecific/WindowsError>
#include <Mib/Core/PlatformSpecific/WindowsString>
#include <Mib/Core/PlatformSpecific/WindowsFilePath>

#include <Windows.h>
#include <lmcons.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <lmapibuf.h>
#include <LsaLookup.h>
#include <Ntsecapi.h>

#pragma comment(lib, "netapi32.lib")

using namespace NMib;

void NMib::NSys::fg_UserManagement_CreateGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr &o_ReturnGID)
{
	LOCALGROUP_INFO_0 GroupInfo;
	NMem::fg_MemClear(GroupInfo);

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

void NMib::NSys::fg_UserManagement_CreateUser
	(
		NMib::NStr::CStr const &_InGroupName
		, NMib::NStr::CStr const &_UserName
		, NMib::NStr::CStrSecure const &_Password
		, NMib::NStr::CStr const &_FullName
		, NMib::NStr::CStr const &_HomeDirectory
		, NMib::NStr::CStr &o_ReturnUID
	)
{
	USER_INFO_1 UserInfo;
	NMem::fg_MemClear(UserInfo);

	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);
	NMib::NStr::CWStr Password = NMib::NStr::NPlatform::fg_StrToWindows<NMib::NStr::CWStrSecure>(_Password);
	NMib::NStr::CWStr FullName = NMib::NStr::NPlatform::fg_StrToWindows(_FullName);
	NMib::NStr::CWStr Comment = NMib::NStr::NPlatform::fg_StrToWindows(NMib::NStr::fg_Format("MalterlibUserGroup: {}", _InGroupName));

	UserInfo.usri1_name = UserName.f_GetStrUniqueWritable();
	UserInfo.usri1_password = Password.f_GetStrUniqueWritable();
	UserInfo.usri1_comment = Comment.f_GetStrUniqueWritable();
	UserInfo.usri1_priv = USER_PRIV_USER;
	UserInfo.usri1_flags = UF_SCRIPT;
	
	uint32 ParmError = 0;
	NET_API_STATUS Status = NetUserAdd(nullptr, 1, (uint8 *)&UserInfo, &ParmError);

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserAdd('{}'), param {}: {}") << _UserName << ParmError << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	USER_INFO_1011 FullNameInfo;
	NMem::fg_MemClear(FullNameInfo);
	FullNameInfo.usri1011_full_name = FullName.f_GetStrUniqueWritable();

	Status = NetUserSetInfo(nullptr, UserName.f_GetStr(), 1011, (uint8 *)&FullNameInfo, nullptr);
	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetUserSetInfo(Set full name): {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

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

 bint NMib::NSys::fg_UserManagement_IsValidName(NMib::NStr::CStr const &_Name)
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

	return UserName;
}

NMib::NStr::CStr NSys::fg_UserManagement_GetProcessRealGroup()
{
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(fg_UserManagement_GetProcessRealUser());

	uint8 *pData = nullptr;
	NET_API_STATUS Status = NetUserGetInfo(nullptr, UserName.f_GetStr(), 10, &pData);

	auto Cleanup = g_OnScopeExit > [&]
		{
			if (pData)
				NetApiBufferFree(pData);
		}
	;

	if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetLocalGroupGetInfo: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	USER_INFO_10 &UserInfo = *((USER_INFO_10 *)pData);

	NMib::NStr::CStr Comment;
	if (UserInfo.usri10_comment)
		Comment = NMib::NStr::CWStr(UserInfo.usri10_comment);

	for (auto &Line : Comment.f_SplitLine())
	{
		if (Line.f_StartsWith("MalterlibUserGroup: "))
			return Line.f_Extract(20);
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

		return GroupName;
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


bint NSys::fg_UserManagement_GroupExists(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr &o_ReturnGID)
{
	NMib::NStr::CWStr GroupName = NMib::NStr::NPlatform::fg_StrToWindows(_GroupName);

	uint8 *pData = nullptr;
	NET_API_STATUS Status = NetLocalGroupGetInfo(nullptr, GroupName.f_GetStr(), 0, &pData);

	auto Cleanup = g_OnScopeExit > [&]
		{
			if (pData)
				NetApiBufferFree(pData);
		}
	;

	if (Status == NERR_GroupNotFound)
		return false;
	else if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetLocalGroupGetInfo: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	o_ReturnGID = _GroupName;
	return true;
}

bint NSys::fg_UserManagement_UserExists(NMib::NStr::CStr const &_UserName, NMib::NStr::CStr &o_ReturnUID)
{
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);

	uint8 *pData = nullptr;
	NET_API_STATUS Status = NetUserGetInfo(nullptr, UserName.f_GetStr(), 0, &pData);

	auto Cleanup = g_OnScopeExit > [&]
		{
			if (pData)
				NetApiBufferFree(pData);
		}
	;

	if (Status == NERR_UserNotFound)
		return false;
	else if (Status != NERR_Success)
		DMibError((NMib::NStr::CFStr256::CFormat("Windows returned an error from NetLocalGroupGetInfo: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Status)).f_GetStr());

	o_ReturnUID = _UserName;
	return true;
}

NMib::NContainer::TCVector<NMib::NStr::CStr> NSys::fg_UserManagement_UserGetMemberOfGroups(NMib::NStr::CStr const &_UserName)
{
	NMib::NStr::CWStr UserName = NMib::NStr::NPlatform::fg_StrToWindows(_UserName);

	uint8 *pData = nullptr;
	uint32 EntriesRead = 0;
	uint32 TotalEntries = 0;
	NET_API_STATUS Status = ERROR_MORE_DATA;
	while (Status == ERROR_MORE_DATA)
		Status = NetUserGetLocalGroups(nullptr, UserName.f_GetStr(), 0, LG_INCLUDE_INDIRECT, &pData, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries);

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

bint NSys::fg_UserManagement_UserIsMemberOfGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	auto Groups = fg_UserManagement_UserGetMemberOfGroups(_UserName);

	for (auto &Group : Groups)
	{
		if (Group == _GroupName)
			return true;
	}

	return false;
}

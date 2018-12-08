// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Process/ProcessLaunch>

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
	NContainer::TCVector<NMib::NStr::CStr> Flags;
	
	Flags =	NContainer::fg_CreateVector<NMib::NStr::CStr>(
		"-d", _HomeDirectory	// Set home directory
		, "-c", _FullName	// Name in comment
		, "-g", _InGroupName		// Login group
		, "-r"				// System account
		, "-s"
		, (_Flags & EUserManagementCreateUserFlag_ShellAccess) ? "/bin/bash" : "/bin/false"
	);

	if (!_Password.f_IsEmpty())
	{
		Flags.f_Insert("--password"); 	// Set Password
		Flags.f_Insert(_Password);
	}

	Flags.f_Insert(_UserName);
	
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	uint32 ExitCode;
	
	if
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/sbin/useradd", Flags, StdOut, StdErr, ExitCode)
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Error creating user {}: /usr/sbin/useradd failed with {}") << _UserName << StdErr);
	}
	
	if (ExitCode == 0)
	{
		if (NSys::fg_UserManagement_UserExists(_UserName, _ReturnUID))
			return;
		DMibError(NMib::NStr::CStr::CFormat("Error creating user {}: Unknown error {} {}") << StdOut << StdErr);
	}
	
	DMibError(NMib::NStr::CStr::CFormat("Error creating user {}: {} {}") << _UserName << ExitCode << StdErr);
}

void NMib::NSys::fg_UserManagement_DeleteUser(NMib::NStr::CStr const &_UserName)
{
	uint32 ExitCode;
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	if
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/sbin/userdel", NContainer::fg_CreateVector<NMib::NStr::CStr>(_UserName), StdOut, StdErr, ExitCode)
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Error deleting user {}: /usr/sbin/groupdel failed with {}") << _UserName << StdErr);
	}

	if (ExitCode == 0)
		return;
	DMibError(NMib::NStr::CStr::CFormat("Error deleting user {}: {} {}") << _UserName << ExitCode << StdErr);
}

void NMib::NSys::fg_UserManagement_CreateGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr &_ReturnGID)
{
	uint32 ExitCode;
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	if
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/sbin/groupadd", NContainer::fg_CreateVector<NMib::NStr::CStr>("-r", _GroupName), StdOut, StdErr, ExitCode)
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Error creating group {}: /usr/sbin/groupadd failed with {}") << _GroupName << StdErr);
	}
	
	if (ExitCode == 0)
	{
		if (NSys::fg_UserManagement_GroupExists(_GroupName, _ReturnGID))
			return;
		DMibError(NMib::NStr::CStr::CFormat("Error creating group {}: Unknown error {} {}") << StdOut << StdErr);
	}

	DMibError(NMib::NStr::CStr::CFormat("Error creating group {}: {} {}") << _GroupName << ExitCode << StdErr);
}

void NMib::NSys::fg_UserManagement_DeleteGroup(NMib::NStr::CStr const &_GroupName)
{
	uint32 ExitCode;
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	if
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/sbin/groupdel", NContainer::fg_CreateVector<NMib::NStr::CStr>(_GroupName), StdOut, StdErr, ExitCode)
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Error deleting group {}: /usr/sbin/groupdel failed with {}") << _GroupName << StdErr);
	}

	if (ExitCode == 0)
		return;
	DMibError(NMib::NStr::CStr::CFormat("Error deleting group {}: {} {}") << _GroupName << ExitCode << StdErr);
}


#if 0
void fg_UserManagement_SetPrimaryGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	uint32 ExitCode;
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	if
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/sbin/usermod", NContainer::fg_CreateVector<NMib::NStr::CStr>("-g", _GroupName, _UserName), StdOut, StdErr, ExitCode)
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Error adding user {} to group {}: /usr/sbin/usermod failed with {}") << _UserName << _GroupName << StdErr);
	}

	if (ExitCode == 0)
		return;
	DMibError(NMib::NStr::CStr::CFormat("Error adding user {} to group {}: {} {}") << _UserName << _GroupName << ExitCode << StdErr);
}
#endif

void NMib::NSys::fg_UserManagement_AddUserToGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	NMib::NStr::CStr AddGID;
	if (!NMib::NSys::fg_UserManagement_GroupExists(_GroupName, AddGID))
		DMibError(NMib::NStr::CStr::CFormat("Error adding user to group: Group '{}' does not exist") << _GroupName);
		
	auto CurrentMembers = NMib::NSys::fg_UserManagement_UserGetMemberOfGroups(_UserName);

	NMib::NStr::CStr NewGroupMembers;
	for (auto &Member : CurrentMembers)
	{
		if (Member == AddGID)
			DMibError(NMib::NStr::CStr::CFormat("Error adding user to group: User '{}' is already a member of group '{}'") << _UserName << _GroupName);
		fg_AddStrSep(NewGroupMembers, Member, ",");
	}

	fg_AddStrSep(NewGroupMembers, AddGID, ",");
	
	uint32 ExitCode;
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	if
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/sbin/usermod", NContainer::fg_CreateVector<NMib::NStr::CStr>("-G", NewGroupMembers, _UserName), StdOut, StdErr, ExitCode)
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Error adding user {} to group {}: /usr/sbin/usermod failed with {}") << _UserName << _GroupName << StdErr);
	}

	if (ExitCode == 0)
		return;
	DMibError(NMib::NStr::CStr::CFormat("Error adding user {} to group {}: {} {}") << _UserName << _GroupName << ExitCode << StdErr);
}

void NMib::NSys::fg_UserManagement_RemoveUserFromGroup(NMib::NStr::CStr const &_GroupName, NMib::NStr::CStr const &_UserName)
{
	NMib::NStr::CStr RemoveGID;
	if (!NMib::NSys::fg_UserManagement_GroupExists(_GroupName, RemoveGID))
		DMibError(NMib::NStr::CStr::CFormat("Error removing user from group: Group '{}' does not exist") << _GroupName);
		
	auto CurrentMembers = NMib::NSys::fg_UserManagement_UserGetMemberOfGroups(_UserName);

	bool bFound = false;
	NMib::NStr::CStr NewGroupMembers;
	for (auto &Member : CurrentMembers)
	{
		if (Member == RemoveGID)
			bFound = true;
		else
			fg_AddStrSep(NewGroupMembers, Member, ",");
	}

	if (!bFound)
		DMibError(NMib::NStr::CStr::CFormat("Error removing user from group: User '{}' is not a member of group '{}'") << _UserName << _GroupName);
	else if (NewGroupMembers.f_IsEmpty())
		DMibError(NMib::NStr::CStr::CFormat("Error removing user from group: Cannot remove '{}' from its last group") << _UserName);
	
	uint32 ExitCode;
	NMib::NStr::CStr StdOut;
	NMib::NStr::CStr StdErr;
	if
		(
			!NMib::NProcess::CProcessLaunch::fs_LaunchBlock("/usr/sbin/usermod", NContainer::fg_CreateVector<NMib::NStr::CStr>("-G", NewGroupMembers, _UserName), StdOut, StdErr, ExitCode)
		)
	{
		DMibError(NMib::NStr::CStr::CFormat("Error adding user {} to group {}: /usr/sbin/usermod failed with {}") << _UserName << _GroupName << StdErr);
	}

	if (ExitCode == 0)
		return;
	DMibError(NMib::NStr::CStr::CFormat("Error adding user {} to group {}: {} {}") << _UserName << _GroupName << ExitCode << StdErr);
}

bint NMib::NSys::fg_UserManagement_IsValidName(NMib::NStr::CStr const &_Name)
{
	// Usernames must start with a lower case letter or an underscore, followed by lower case letters, digits, underscores, or dashes.
	// They can end with a dollar sign. In regular expression terms: [a-z_][a-z0-9_-]*[$]?
	
	aint iParse = 0;
	aint LastPos = _Name.f_GetLen()-1;
	ch32 Current = _Name.f_GetAt(iParse);
	while (Current)
	{
		if (!(NMib::NStr::fg_CharIsAnsiAlphabetical(Current) && NMib::NStr::fg_CharLowerCase(Current) == Current)
			&& !(Current == '_')
			&& !(NMib::NStr::fg_CharIsNumber(Current) && iParse > 0)
			&& !(Current == '-' && iParse > 0)
			&& !(Current == '$' && iParse == LastPos))
			return false;

		Current = _Name.f_GetAt(++iParse);
	}

	return true;
}


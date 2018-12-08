// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Cryptography/Hashes/SHA>

#include "Malterlib_Security_UniqueUserGroup.h"

namespace NMib::NSecurity
{
	using namespace NStr;

	CUniqueUserGroup::CUniqueUserGroup(CStr const &_DefaultDirectory)
	{
		CStr ProgramDirectory = NFile::CFile::fs_GetProgramDirectory();
		if (ProgramDirectory == _DefaultDirectory)
		{
			m_UserGroupNameTransform = "{}";
			return;
		}

		NCryptography::CHash_SHA256 Hash;

		CStr Salt = "MalterlibSecurityUserGroupNameTransform";

		Hash.f_AddData(Salt.f_GetStr(), Salt.f_GetLen());
		Hash.f_AddData(_DefaultDirectory.f_GetStr(), _DefaultDirectory.f_GetLen());
		Hash.f_AddData(ProgramDirectory.f_GetStr(), ProgramDirectory.f_GetLen());
		m_UserGroupNameTransform = "{{}_{}"_f << Hash.f_GetDigest().f_GetString().f_Left(16);
	}

	CStr CUniqueUserGroup::f_TransformUserGroup(CStr const &_Name) const
	{
		if (_Name.f_IsEmpty())
			return {};

		return CStr::CFormat(m_UserGroupNameTransform) << _Name;
	}

	CStr CUniqueUserGroup::f_GetUser(CStr const &_Name) const
	{
		if (_Name.f_IsEmpty())
			return {};

		return NSys::fg_UserManagement_MakeValidUserName(f_TransformUserGroup(_Name));
	}

	CStr CUniqueUserGroup::f_GetGroup(CStr const &_Name) const
	{
		if (_Name.f_IsEmpty())
			return {};

#ifdef DPlatformFamily_Windows
		return NSys::fg_UserManagement_MakeValidGroupName("Group_" + f_TransformUserGroup(_Name));
#else
		return NSys::fg_UserManagement_MakeValidGroupName(f_TransformUserGroup(_Name));
#endif
	}
}

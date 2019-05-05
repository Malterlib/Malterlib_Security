// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>

namespace NMib::NSecurity
{
	struct CUniqueUserGroup
	{
		CUniqueUserGroup(NStr::CStr const &_DefaultDirectory, NStr::CStr const &_CurrentDirectory = NFile::CFile::fs_GetProgramDirectory());

		NStr::CStr f_GetUser(NStr::CStr const &_Name) const;
		NStr::CStr f_GetGroup(NStr::CStr const &_Name) const;
		NStr::CStr f_TransformUserGroup(NStr::CStr const &_Name) const;

		NStr::CStr m_UserGroupNameTransform;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NSecurity;
#endif

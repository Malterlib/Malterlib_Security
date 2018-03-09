// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Cryptography/Hashes/SHA>
#include <Mib/Core/PlatformSpecific/WindowsRegistry>

#include <Windows.h>
#include <wincrypt.h>

namespace 
{
	struct CSubSystem_Security_Platform_Windows_SecurePassword : public NMib::CSubSystem
	{
		NMib::NStr::CStr m_SecurePasswordLocation;
	};

	NMib::TCSubSystem<CSubSystem_Security_Platform_Windows_SecurePassword, NMib::ESubSystemDestruction_BeforeMemoryManager> g_SubSystem_Security_Platform_Windows_SecurePassword = {DAggregateInit};
}

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_SetLocation(NMib::NStr::CStr const& _Location)
{
	auto &SubSystem = *g_SubSystem_Security_Platform_Windows_SecurePassword;
	SubSystem.m_SecurePasswordLocation = _Location;
	return NMib::NSys::ESecurePassword_OK;
}

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Store(NMib::NStr::CStr const& _Key, NMib::NStr::CStrSecure const& _Password)
{
	auto &SubSystem = *g_SubSystem_Security_Platform_Windows_SecurePassword;

	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB Entropy;

	DataIn.pbData = (BYTE*)_Password.f_GetStr();    
	DataIn.cbData = _Password.f_GetLen();

	NDataProcessing::CHashDigest_SHA1 KeyDigest;
	{
		NDataProcessing::CHash_SHA1 Hash;
		Hash.f_AddData(_Key.f_GetStr(), _Key.f_GetLen());
		KeyDigest = Hash;
	}
	Entropy.pbData = (BYTE*)KeyDigest.f_GetData();
	Entropy.cbData = NDataProcessing::CHashDigest_SHA1::fs_GetSize();

	if(!CryptProtectData(
		&DataIn
		,NULL 			// Description
		,&Entropy 			// Optional entropy
		,NULL 			// Reserved
		,NULL 			// Prompt info
		,0 				// Flags
		,&DataOut))
	{
		return NMib::NSys::ESecurePassword_Failure;
	}

	NContainer::TCVector<uint8> Encrypted;

	Encrypted.f_SetLen(DataOut.cbData);
	NMem::fg_MemCopy(Encrypted.f_GetArray(), DataOut.pbData, Encrypted.f_GetLen());

	SecureZeroMemory(DataOut.pbData, DataOut.cbData);
	LocalFree(DataOut.pbData);

	auto Cleanup = fg_OnScopeExit(
			[&]()
			{
				SecureZeroMemory(Encrypted.f_GetArray(), Encrypted.f_GetLen());
			}
		);

	NMib::NPlatform::CWin32_Registry Reg(NMib::NPlatform::CWin32_Registry::ERegRoot_CurrentUser, SubSystem.m_SecurePasswordLocation);

	try
	{
		Reg.f_Write("", _Key, Encrypted);
	}
	catch (const NException::CException &)
	{
		return NMib::NSys::ESecurePassword_Failure;
	}

	return NMib::NSys::ESecurePassword_OK;
}

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Remove(NMib::NStr::CStr const& _Key)
{
	auto &SubSystem = *g_SubSystem_Security_Platform_Windows_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

	NMib::NPlatform::CWin32_Registry Reg(NMib::NPlatform::CWin32_Registry::ERegRoot_CurrentUser, SubSystem.m_SecurePasswordLocation);

	try
	{
		if (Reg.f_ValueExists("", _Key))
			Reg.f_DeleteValue("", _Key);
		else
			return NMib::NSys::ESecurePassword_NotFound;
	}
	catch(NException::CException const&)
	{
		return NMib::NSys::ESecurePassword_Failure;
	}

	return NMib::NSys::ESecurePassword_OK;
}

NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Get(NMib::NStr::CStr const& _Key, NMib::NStr::CStrSecure& _oPassword)
{
	auto &SubSystem = *g_SubSystem_Security_Platform_Windows_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

	NMib::NPlatform::CWin32_Registry Reg(NMib::NPlatform::CWin32_Registry::ERegRoot_CurrentUser, SubSystem.m_SecurePasswordLocation);

	NContainer::TCVector<uint8> Encrypted;

	try
	{
		Encrypted = Reg.f_Read_Bin("", _Key);
	}
	catch(NException::CException const&)
	{
		return NMib::NSys::ESecurePassword_NotFound;
	}

	DATA_BLOB DataIn;
	DATA_BLOB DataOut = {0};

	DataIn.pbData = (BYTE*)Encrypted.f_GetArray();
	DataIn.cbData = Encrypted.f_GetLen();

	auto Cleanup = fg_OnScopeExit(
			[&]()
			{
				SecureZeroMemory(Encrypted.f_GetArray(), Encrypted.f_GetLen());
				if (DataOut.pbData)
				{
					SecureZeroMemory(DataOut.pbData, DataOut.cbData);
					LocalFree(DataOut.pbData);
				}
			}
		);

	NDataProcessing::CHashDigest_SHA1 KeyDigest;
	{
		NDataProcessing::CHash_SHA1 Hash;
		Hash.f_AddData(_Key.f_GetStr(), _Key.f_GetLen());
		KeyDigest = Hash;
	}

	DATA_BLOB Entropy;
	Entropy.pbData = (BYTE*)KeyDigest.f_GetData();
	Entropy.cbData = NDataProcessing::CHashDigest_SHA1::fs_GetSize();


	if (!CryptUnprotectData(
				&DataIn
			,	NULL 	// Desc
			,	&Entropy 	// Entropy
			,	NULL 	// Reserved
			,	NULL 	// Prompt
			,	0 		// Flags
			, 	&DataOut
		))
	{
		return NMib::NSys::ESecurePassword_Failure;
	}

	_oPassword = NMib::NStr::CStrSecure( (char*)DataOut.pbData, DataOut.cbData );

	return NMib::NSys::ESecurePassword_OK;

}

bool NMib::NSys::fg_SecurePassword_Supported()
{
	return true;
}


NMib::NSys::ESecurePassword NMib::NSys::fg_SecurePassword_Exists(NMib::NStr::CStr const& _Key)
{
	auto &SubSystem = *g_SubSystem_Security_Platform_Windows_SecurePassword;
	DMibSafeCheck(!SubSystem.m_SecurePasswordLocation.f_IsEmpty(), "You must have set the location for secure passwords.");

	NMib::NPlatform::CWin32_Registry Reg(NMib::NPlatform::CWin32_Registry::ERegRoot_CurrentUser, SubSystem.m_SecurePasswordLocation);

	try
	{
		if (Reg.f_ValueExists("", _Key))
		{
			return NMib::NSys::ESecurePassword_OK;
		}
	}
	catch(NException::CException const&)
	{
		return NMib::NSys::ESecurePassword_Failure;
	}

	return NMib::NSys::ESecurePassword_NotFound;
}

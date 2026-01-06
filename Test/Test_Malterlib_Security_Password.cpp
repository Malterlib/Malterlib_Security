// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>

using namespace NMib;

namespace
{

	class CSecurePassword_Tests : public NMib::NTest::CTest
	{
	public:

		void f_DoTests()
		{
			if (!NSys::fg_SecurePassword_Supported() || NSys::fg_SecurePassword_IsLocked())
				return; // Not supported

#ifdef DPlatformFamily_macOS
			if (!fg_GetSys()->f_GetEnvironmentVariable("SSH_CLIENT").f_IsEmpty())
				return;
#endif

			NStr::CStr TestKey = "TestKey";
			NStr::CStrSecure TestPassword = "TestPassword";

			NStr::CStr TestNonExistingKey = "TestKeyNonExisting";

			DMibTestSuite("General")
			{
				{
					DMibTestPath("SetLocation");
					NStr::CStr Location;

					#ifdef DPlatformFamily_Windows
						Location = "Software\\Malterlib\\MalterlibTests_General\\SecureStore";
					#else
						Location = "MalterlibTests_General";

					#endif

					NSys::ESecurePassword SetLocationRet = NSys::fg_SecurePassword_SetLocation(Location);

					DMibTest(DMibExpr(SetLocationRet) == DMibExpr(NSys::ESecurePassword_OK));
				}
				{
					DMibTestPath("Store");
					NSys::ESecurePassword StoreRet = NSys::fg_SecurePassword_Store(TestKey, TestPassword);
					DMibTest(DMibExpr(StoreRet) == DMibExpr(NSys::ESecurePassword_OK));

					NSys::ESecurePassword StoreAgainRet = NSys::fg_SecurePassword_Store(TestKey, TestPassword);
					DMibTest(DMibExpr(StoreAgainRet) == DMibExpr(NSys::ESecurePassword_OK));
				}
				{
					DMibTestPath("Exists");
					NStr::CStrSecure Password;

					NSys::ESecurePassword ExistsRet = NSys::fg_SecurePassword_Exists(TestKey);
					DMibTest(DMibExpr(ExistsRet) == DMibExpr(NSys::ESecurePassword_OK));

					NSys::ESecurePassword FailedExistsRet = NSys::fg_SecurePassword_Exists(TestNonExistingKey);
					DMibTest(DMibExpr(FailedExistsRet) == DMibExpr(NSys::ESecurePassword_NotFound));
				}
				{
					DMibTestPath("Get");
					NStr::CStrSecure Password;

					NSys::ESecurePassword GetRet = NSys::fg_SecurePassword_Get(TestKey, Password);
					DMibTest(DMibExpr(GetRet) == DMibExpr(NSys::ESecurePassword_OK));

					DMibTest(DMibExpr(Password) == DMibExpr(TestPassword));

					NSys::ESecurePassword FailedGetRet = NSys::fg_SecurePassword_Get(TestNonExistingKey, Password);
					DMibTest(DMibExpr(FailedGetRet) == DMibExpr(NSys::ESecurePassword_NotFound));
				}
				{
					DMibTestPath("Remove");
					NStr::CStrSecure Password;

					NSys::ESecurePassword RemoveRet = NSys::fg_SecurePassword_Remove(TestKey);
					DMibTest(DMibExpr(RemoveRet) == DMibExpr(NSys::ESecurePassword_OK));

					NSys::ESecurePassword ExistsRet = NSys::fg_SecurePassword_Exists(TestKey);
					DMibTest(DMibExpr(ExistsRet) == DMibExpr(NSys::ESecurePassword_NotFound));

					NSys::ESecurePassword FailedRemoveRet = NSys::fg_SecurePassword_Remove(TestNonExistingKey);
					DMibTest(DMibExpr(FailedRemoveRet) == DMibExpr(NSys::ESecurePassword_NotFound));
				}
			};
		}
	};

	DMibTestRegister(CSecurePassword_Tests, Malterlib::Security);

}

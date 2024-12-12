// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Test/Performance>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/RandomID>

using namespace NMib::NStr;

namespace
{
	class CUser_Tests : public NMib::NTest::CTest
	{
	public:

		void f_DoTests()
		{
			using namespace NMib::NSys;

			DMibTestSuite("Name validation")
			{
				bool bAllLowerCase = true;

				bool bWithDigit = true;
				bool bDigitFirst = true;

				bool bUnderscoreFirst = true;
				bool bWithUnderscore = true;

				bool bWithDollarSign = true;
				bool bDollarSignLast = true;

				bool bUppercaseFirst = true;
				bool bWithUppercase = true;
				bool bWithSpace = true;

#if defined(DPlatformFamily_Windows)
#elif defined(DPlatformFamily_macOS)
				bWithSpace = false;
#elif defined(DPlatformFamily_Linux)
				bDigitFirst = false;
				bWithDollarSign = false;

				bUppercaseFirst = false;
				bWithUppercase = false;
				bWithSpace = false;
#endif

				DMibTest(DMibExpr(fg_UserManagement_IsValidName("valid")) == DMibExpr(bAllLowerCase));

				DMibTest(DMibExpr(fg_UserManagement_IsValidName("val1d")) == DMibExpr(bWithDigit));
				DMibTest(DMibExpr(fg_UserManagement_IsValidName("1valid")) == DMibExpr(bDigitFirst));


				DMibTest(DMibExpr(fg_UserManagement_IsValidName("val_id")) == DMibExpr(bWithUnderscore));
				DMibTest(DMibExpr(fg_UserManagement_IsValidName("_valid")) == DMibExpr(bUnderscoreFirst));

				DMibTest(DMibExpr(fg_UserManagement_IsValidName("val$id")) == DMibExpr(bWithDollarSign));
				DMibTest(DMibExpr(fg_UserManagement_IsValidName("valid$")) == DMibExpr(bDollarSignLast));

				DMibTest(DMibExpr(fg_UserManagement_IsValidName("Valid")) == DMibExpr(bUppercaseFirst));
				DMibTest(DMibExpr(fg_UserManagement_IsValidName("valiD")) == DMibExpr(bWithUppercase));

				DMibTest(DMibExpr(fg_UserManagement_IsValidName("val id")) == DMibExpr(bWithSpace));
			};
			DMibTestSuite("Read Only")
			{
				DMibExpect(fg_UserManagement_GetProcessRealUser(), !=, "");
				DMibExpect(fg_UserManagement_GetProcessEffectiveUser(), !=, "");

				DMibExpect(fg_UserManagement_GetProcessRealGroup(), !=, "");
				DMibExpect(fg_UserManagement_GetProcessEffectiveGroup(), !=, "");

				DMibExpect(fg_UserManagement_GetProcessRealUserName(), !=, "");
				DMibExpect(fg_UserManagement_GetProcessEffectiveUserName(), !=, "");

				DMibExpect(fg_UserManagement_GetProcessRealGroupName(), !=, "");
				DMibExpect(fg_UserManagement_GetProcessEffectiveGroupName(), !=, "");
			};

			DMibTestSuite(CTestCategory("General") << CTestGroup("SuperUser"))
			{
				CStr TestGroup = "_MalterlibTestGroup";
				CStr TestGroup2 = "_MalterlibTestGroup2";
				CStr TestUser = "_MalterlibTestUser";
				CStrSecure TestPassword = NMib::NCryptography::fg_RandomID() + "1aA@";

#if defined(DPlatformFamily_Windows)
				CStr ExistingUser = "Administrator";
				CStr ExistingGroup = "Administrators";
#elif defined(DPlatformFamily_Linux)
				CStr ExistingUser = "root";
				CStr ExistingGroup = "root";
#else
				CStr ExistingUser = "root";
				CStr ExistingGroup = "wheel";
#endif

				CStr ReturnGID;
				CStr ReturnUID;

				{
					if (fg_UserManagement_UserExists(TestUser, ReturnUID))
						fg_UserManagement_DeleteUser(TestUser);

					if (fg_UserManagement_GroupExists(TestGroup, ReturnGID))
						fg_UserManagement_DeleteGroup(TestGroup);

					if (fg_UserManagement_GroupExists(TestGroup2, ReturnGID))
						fg_UserManagement_DeleteGroup(TestGroup2);
				}

				{
					DMibTestPath("Groups exists");
					DMibTest(!DMibExpr(fg_UserManagement_GroupExists(TestGroup, ReturnGID)));
					DMibTest(DMibExpr(fg_UserManagement_GroupExists(ExistingGroup, ReturnGID)) == DMibExpr(true));
				}

				{
					DMibTestPath("Groups create");
					CStr CreatedGID;
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_CreateGroup(TestGroup, CreatedGID)));
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_CreateGroup(TestGroup2, ReturnGID)));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_CreateGroup(TestGroup, ReturnGID)));
					DMibTest(DMibExpr(fg_UserManagement_GroupExists(TestGroup, ReturnGID)));
					DMibTest(DMibExpr(CreatedGID) == DMibExpr(ReturnGID));

				};

				{
					DMibTestPath("Users exists");
					DMibTest(DMibExpr(fg_UserManagement_UserExists(TestUser, ReturnUID)) == DMibExpr(false));
					DMibTest(DMibExpr(fg_UserManagement_UserExists(ExistingUser, ReturnUID)) == DMibExpr(true));
				};

				{
					DMibTestPath("Users create");
					CStr CreatedUID;
					DMibTest
						(
							DMibExpr(TCThrowsException<>())
							== DMibLExpr
							(
								fg_UserManagement_CreateUser
								(
									TestGroup
									, TestUser
									, TestPassword
									, "Test FullName"
									, NMib::NFile::CFile::fs_GetProgramDirectory()
									, CreatedUID
									, NMib::NSys::EUserManagementCreateUserFlag_None
								)
							)
						)
					;

					DMibTest
						(
							DMibExpr(TCThrowsException<NMib::NException::CException>())
							== DMibLExpr
							(
								fg_UserManagement_CreateUser
								(
									TestGroup
									, TestUser
									, TestPassword
									, "Test FullName"
									, NMib::NFile::CFile::fs_GetProgramDirectory()
									, ReturnUID
									, NMib::NSys::EUserManagementCreateUserFlag_None
								)
							)
						)
					;

					DMibTest(DMibExpr(fg_UserManagement_UserExists(TestUser, ReturnUID)));
					DMibTest(DMibExpr(CreatedUID) == DMibExpr(ReturnUID));

					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr(true));
				};

				{
					DMibTestPath("Add user to group");
					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr(false));

					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_AddUserToGroup(TestGroup2, TestUser)));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_AddUserToGroup(TestGroup2, TestUser)));

					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr(true));
					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr(true));
				};

				{
					DMibTestPath("Remove user from group");

					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_RemoveUserFromGroup(TestGroup2, TestUser)));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_RemoveUserFromGroup(TestGroup2, TestUser)));
#if !defined(DPlatformFamily_Windows)
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_RemoveUserFromGroup(TestGroup, TestUser)));
#endif

					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr(true));
					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr(false));
				};

				{
					DMibTestPath("Users delete");
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_DeleteUser(TestUser)));
					DMibTest(DMibExpr(fg_UserManagement_UserExists(TestUser, ReturnUID)) == DMibExpr(false));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_DeleteUser(TestUser)));
				};

				{
					DMibTestPath("Groups delete");
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_DeleteGroup(TestGroup)));
					DMibTest(DMibExpr(fg_UserManagement_GroupExists(TestGroup, ReturnUID)) == DMibExpr(false));
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_DeleteGroup(TestGroup2)));
					DMibTest(DMibExpr(fg_UserManagement_GroupExists(TestGroup2, ReturnUID)) == DMibExpr(false));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_DeleteGroup(TestGroup)));
				};
			};
		}
	};

	DMibTestRegister(CUser_Tests, Malterlib::Security);
}

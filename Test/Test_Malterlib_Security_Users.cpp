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
				bint bAllLowerCase = true;
				
				bint bWithDigit = true;
				bint bDigitFirst = true;
				
				bint bUnderscoreFirst = true;
				bint bWithUnderscore = true;
				
				bint bWithDollarSign = true;
				bint bDollarSignLast = true;
				
				bint bUppercaseFirst = true;
				bint bWithUppercase = true;
				bint bWithSpace = true;
				
#if defined(DPlatformFamily_Windows)
#elif defined(DPlatformFamily_OSX)
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
			
			DMibTestSuite(CTestCategory("General") << CTestGroup("Manual"))
			{
				CStr TestGroup = "_MalterlibTestGroup";
				CStr TestGroup2 = "_MalterlibTestGroup2";
				CStr TestUser = "_MalterlibTestUser";
				CStrSecure TestPassword = NMib::NCryptography::fg_RandomID() + "1aA@";
				
#if defined(DPlatformFamily_Windows)
				CStr ExistingUser = "Administrator";
				CStr ExistingGroup = "Administrators";
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
					DMibTest(DMibExpr(fg_UserManagement_GroupExists(ExistingGroup, ReturnGID)) == DMibExpr(bint(true)));
					
				}
				
				{
					DMibTestPath("Groups create");
					CStr CreatedGID;
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_CreateGroup(TestGroup, CreatedGID)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_CreateGroup(TestGroup2, ReturnGID)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_CreateGroup(TestGroup, ReturnGID)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(fg_UserManagement_GroupExists(TestGroup, ReturnGID)));
					DMibTest(DMibExpr(CreatedGID) == DMibExpr(ReturnGID));
					
				};

				{
					DMibTestPath("Users exists");
					DMibTest(DMibExpr(fg_UserManagement_UserExists(TestUser, ReturnUID)) == DMibExpr((bint)false));
					DMibTest(DMibExpr(fg_UserManagement_UserExists(ExistingUser, ReturnUID)) == DMibExpr((bint)true));
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
						(ETestFlag_NoValues)
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
						(ETestFlag_NoValues)
					;
					
					DMibTest(DMibExpr(fg_UserManagement_UserExists(TestUser, ReturnUID)));
					DMibTest(DMibExpr(CreatedUID) == DMibExpr(ReturnUID));

					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr((bint)true));
				};
				
				{
					DMibTestPath("Add user to group");
					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr((bint)false));
					
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_AddUserToGroup(TestGroup2, TestUser)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_AddUserToGroup(TestGroup2, TestUser)))(ETestFlag_NoValues);
					
					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr((bint)true));
					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr((bint)true));
				};
				
				{
					DMibTestPath("Remove user from group");
					
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_RemoveUserFromGroup(TestGroup2, TestUser)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_RemoveUserFromGroup(TestGroup2, TestUser)))(ETestFlag_NoValues);
#if !defined(DPlatformFamily_Windows)
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_RemoveUserFromGroup(TestGroup, TestUser)))(ETestFlag_NoValues);
#endif

					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr((bint)true));
					DMibTest(DMibExpr(fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr((bint)false));
				};
				
				{
					DMibTestPath("Users delete");
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_DeleteUser(TestUser)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(fg_UserManagement_UserExists(TestUser, ReturnUID)) == DMibExpr((bint)false));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_DeleteUser(TestUser)))(ETestFlag_NoValues);
				};
				
				{
					DMibTestPath("Groups delete");
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_DeleteGroup(TestGroup)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(fg_UserManagement_GroupExists(TestGroup, ReturnUID)) == DMibExpr((bint)false));
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(fg_UserManagement_DeleteGroup(TestGroup2)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(fg_UserManagement_GroupExists(TestGroup2, ReturnUID)) == DMibExpr((bint)false));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(fg_UserManagement_DeleteGroup(TestGroup)))(ETestFlag_NoValues);
				};
			};
		}
	};
	
	DMibTestRegister(CUser_Tests, Malterlib::Security);
}

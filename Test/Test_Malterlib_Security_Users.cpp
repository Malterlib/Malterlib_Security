// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Test/Performance>
#include <Mib/Test/Exception>

using namespace NMib::NStr;

#if defined(DPlatformFamily_Windows)

	#pragma message ( "TODO: Implement user/group management for Windows." )

#else

namespace 
{
	class CUser_Tests : public NMib::NTest::CTest
	{
	public:

		void f_DoTests()
		{
			
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
				
				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("valid")) == DMibExpr(bAllLowerCase));
				
				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("val1d")) == DMibExpr(bWithDigit));
				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("1valid")) == DMibExpr(bDigitFirst));
				

				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("val_id")) == DMibExpr(bWithUnderscore));
				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("_valid")) == DMibExpr(bUnderscoreFirst));

				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("val$id")) == DMibExpr(bWithDollarSign));
				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("valid$")) == DMibExpr(bDollarSignLast));
				
				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("Valid")) == DMibExpr(bUppercaseFirst));
				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("valiD")) == DMibExpr(bWithUppercase));
				
				DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_IsValidName("val id")) == DMibExpr(bWithSpace));
			};
			
			DMibTestSuite(CTestCategory("General") << CTestGroup("Manual"))
			{
				CStr TestGroup = "_hansoftidstestgroup";
				CStr TestGroup2 = "_hansoftidstestgroup2";
				CStr TestUser = "_hansoftidstestuser";
				
				CStr ExistingUser = "root";
				CStr ExistingGroup = "wheel";

				CStr ReturnGID;
				CStr ReturnUID;
				
				{
					if (NMib::NSys::fg_UserManagement_UserExists(TestUser, ReturnUID))
						NMib::NSys::fg_UserManagement_DeleteUser(TestUser);
					
					if (NMib::NSys::fg_UserManagement_GroupExists(TestGroup, ReturnGID))
						NMib::NSys::fg_UserManagement_DeleteGroup(TestGroup);

					if (NMib::NSys::fg_UserManagement_GroupExists(TestGroup2, ReturnGID))
						NMib::NSys::fg_UserManagement_DeleteGroup(TestGroup2);
				}
				
				{
					DMibTestPath("Groups exists");
					DMibTest(!DMibExpr(NMib::NSys::fg_UserManagement_GroupExists(TestGroup, ReturnGID)));
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_GroupExists(ExistingGroup, ReturnGID)) == DMibExpr(bint(true)));
					
				}
				
				{
					DMibTestPath("Groups create");
					CStr CreatedGID;
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(NMib::NSys::fg_UserManagement_CreateGroup(TestGroup, CreatedGID)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(NMib::NSys::fg_UserManagement_CreateGroup(TestGroup2, ReturnGID)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(NMib::NSys::fg_UserManagement_CreateGroup(TestGroup, ReturnGID)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_GroupExists(TestGroup, ReturnGID)));
					DMibTest(DMibExpr(CreatedGID) == DMibExpr(ReturnGID));
					
				};

				{
					DMibTestPath("Users exists");
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserExists(TestUser, ReturnUID)) == DMibExpr((bint)false));
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserExists(ExistingUser, ReturnUID)) == DMibExpr((bint)true));
				};
				
				{
					DMibTestPath("Users create");
					CStr CreatedUID;
					DMibTest(DMibExpr(TCThrowsException<>()) ==
								 DMibLExpr(NMib::NSys::fg_UserManagement_CreateUser(TestGroup,
																					TestUser,
																					"Test Password",
																					"Test FullName",
																					NMib::NFile::CFile::fs_GetProgramDirectory(), CreatedUID)))(ETestFlag_NoValues);
					
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) ==
								 DMibLExpr(NMib::NSys::fg_UserManagement_CreateUser(TestGroup,
																					TestUser,
																					"Test Password",
																					"Test FullName",
																					NMib::NFile::CFile::fs_GetProgramDirectory(), ReturnUID)))(ETestFlag_NoValues);
					
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserExists(TestUser, ReturnUID)));
					DMibTest(DMibExpr(CreatedUID) == DMibExpr(ReturnUID));

					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr((bint)true));
				};
				
				{
					DMibTestPath("Add user to group");
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr((bint)false));
					
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(NMib::NSys::fg_UserManagement_AddUserToGroup(TestGroup2, TestUser)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(NMib::NSys::fg_UserManagement_AddUserToGroup(TestGroup2, TestUser)))(ETestFlag_NoValues);
					
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr((bint)true));
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr((bint)true));
				};
				
				{
					DMibTestPath("Remove user from group");
					
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(NMib::NSys::fg_UserManagement_RemoveUserFromGroup(TestGroup2, TestUser)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(NMib::NSys::fg_UserManagement_RemoveUserFromGroup(TestGroup2, TestUser)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(NMib::NSys::fg_UserManagement_RemoveUserFromGroup(TestGroup, TestUser)))(ETestFlag_NoValues);

					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(TestGroup, TestUser)) == DMibExpr((bint)true));
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserIsMemberOfGroup(TestGroup2, TestUser)) == DMibExpr((bint)false));
				};
				
				{
					DMibTestPath("Users delete");
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(NMib::NSys::fg_UserManagement_DeleteUser(TestUser)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_UserExists(TestUser, ReturnUID)) == DMibExpr((bint)false));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(NMib::NSys::fg_UserManagement_DeleteUser(TestUser)))(ETestFlag_NoValues);
				};
				
				{
					DMibTestPath("Groups delete");
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(NMib::NSys::fg_UserManagement_DeleteGroup(TestGroup)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_GroupExists(TestGroup, ReturnUID)) == DMibExpr((bint)false));
					DMibTest(DMibExpr(TCThrowsException<>()) == DMibLExpr(NMib::NSys::fg_UserManagement_DeleteGroup(TestGroup2)))(ETestFlag_NoValues);
					DMibTest(DMibExpr(NMib::NSys::fg_UserManagement_GroupExists(TestGroup2, ReturnUID)) == DMibExpr((bint)false));
					DMibTest(DMibExpr(TCThrowsException<NMib::NException::CException>()) == DMibLExpr(NMib::NSys::fg_UserManagement_DeleteGroup(TestGroup)))(ETestFlag_NoValues);
				};
			};
		}
	};
	
	DMibTestRegister(CUser_Tests, Malterlib::Security);
}

#endif

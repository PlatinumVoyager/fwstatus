#include <Windows.h>

#pragma comment(lib, "advapi32.lib")

// Check if user is within the bounds of the administrative group SID (Windows Security Identifier)


int main(void)
{
    PSID adminGroup;
    BOOL hasPriv = FALSE;
    SID_IDENTIFIER_AUTHORITY winNtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&winNtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        // check if the admin security identifier is enabled in the current access token of the calling process.
        if (!CheckTokenMembership(NULL, adminGroup, &hasPriv))
        {
            hasPriv = FALSE;
        }
        else
        {
            hasPriv = TRUE;
        }

        FreeSid(adminGroup);
    }

    switch (hasPriv)
    {
        case 1:
            printf("You have administrative capabilities.\n");
            break;

        case 0:
            printf("You do not possess the required resource manipulation constructs.\n");
            break;
    }

    return 0;
}
#include <Windows.h> // let windows import first (priority)
#include <oleauto.h>
#include <netfw.h>
#include <wchar.h>
#include <stdbool.h>

/*
    THIS TOOL MANIPULATES THE PROFILER STATUS OF EACH OF THE 3 WINDOWS DEFENDER FIREWALL
    SUBDOMAINS/SUBLISTINGS (DOMAIN, PRIVATE, PUBLIC or *) AND PRINTS LISTINGS TO STDOUT
*/

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")

#define UTILITY_VERSION "(version: 1.00)"

#define MAX_ARRAY 5
#define PROGRAM_ENTRY 1

/*
    Determine the flag feature set when calling the global firewall manipulation request helper function
    this enables `firewallstatus` to direct execution of enabling and/or disabling the Windows Defender profiler sublisting
    targets from an individual helper function instead of declaring function prototypes for multiple adjacent helper functions
    relating to the manipulation of the Windows Defender Firewall (enable, disable, etc)
*/
#define SET_FLAG_ENABLE -1
#define SET_FLAG_DISABLE 0

// --------------------START------------------------
// Execution options for disabling Windows Firewall
#define NFWP2_DOMAIN 1
#define NFWP2_PUBLIC 2
#define NFWP2_PRIVATE 3
#define PRIMITIVE_ALL_CHECK 0

// define SYMBOLIC CONSTANTS that will enable us to determine which profiler targets were disabled when calling "*" or "ALL"
// these values MUST be set whenever a target profiler is manipulated either via enabling or disabling it
int DISABLE_PUBLIC_PROFILER = 0;
int DISABLE_PRIVATE_PROFILER = 0;
int DISABLE_DOMAIN_PROFILER = 0;

volatile int NETFWP2_CODE = -1;
// --------------------END--------------------------

// symbolic constant (define directive) for discarding the network forwarding table (INetFwPolicy2 struct)
#define DISCARD_NETPOLICY_HANDLE pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2)
#define PROFILER_STRING "[+] Windows Defender Firewall target priority set to:"

#define GRACEFUL_PROFILER_HANDLE {\
                printf("ERROR: You must suppliment a sufficient target profiler!\n");\
                \
                return -1;\
            }

wchar_t *RETURN_ERROR_DISABLE[2] = {L"** Failed to disable the Windows Defender Firewall ", L". Re-run with Administrative privileges!\n"};

// initialize primary profiler target and helper function prototypes
void ReturnHelpStatus(void);

// target profiler sublisting helper function prototypes
void GetAllProfilerStatus(INetFwPolicy2 *pNetFwPolicy2);
void GetDomainProfilerStatus(INetFwPolicy2 *pNetFwPolicy2, int opt_no_quit);
void GetPrivateProfilerStatus(INetFwPolicy2 *pNetFwPolicy2, int opt_no_quit);
void GetPublicProfileStatus(INetFwPolicy2 *pNetFwPolicy2, int opt_no_quit);

// windows defender firewall global routing manipulation option helper function prototypes
void EnableWindowsFirewall(INetFwPolicy2 *pNetFwPolicy2, LPWSTR *sublisting);
void DisableWindowsFirewall(INetFwPolicy2 *pNetFwPolicy2, LPWSTR *substring);
void HandleFwManipulationRequest(INetFwPolicy2 *pNetFwPolicy2, LPWSTR *sublisting, int set_flag);


int main(int argc, wchar_t *argv[])
{
    /*
        perform POST operation PRE administrative checks for targeted current access token SID (ADMIN GROUP)
        whilst also checking if the current program is being run with administrative capabilities
    
        perform the checks ONLY when executing high level order profiler manipulation operations (i.e -d, -e, etc.)
    */

    if (argc < 2)
    {
        ReturnHelpStatus();
    }

    int argvCount;
    size_t setCount = 0;

    LPWSTR *argList = CommandLineToArgvW(GetCommandLineW(), &argvCount);

    // literal options to pass to the '-s', '-d', and '-e' arguments (Ex: ".\firewallstatus.exe -s DOMAIN/PRIVATE/PUBLIC/*/ALL")
    wchar_t *GLOBAL_PROFILER_OPTIONS[] = {
        L"DOMAIN",
        L"PRIVATE",
        L"PUBLIC",
        L"*",
        L"ALL"
    };

    // CoInitialize() is used to initialize the COM (component object model) on the current thread
    // and identifies the concurrency model as a single-thread apartment (STA)
    // it is also required to call CoInitialize() in order to be able to call other library functions
    // to obtain a pointer to the standard allocator, and the memory allocation functions
    HRESULT hResult = CoInitialize(NULL);

    INetFwPolicy2 *pNetFwPolicy2 = NULL;

    int opt_no_quit = 1; // can be set to an arbitrary value. GetAllProfilerStatus() => sets 'int opt_no_quit = 1;' to bypass function quitting

    if (FAILED(hResult))
    {
        printf("Failed to initialize COM library. Error code: 0x%08X\n", hResult);
        return -1;
    }

    hResult = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    
    if (FAILED(hResult))
    {
        printf("Failed to create INetFwPolicy2 instance. Error code: 0x%08X\n", hResult);

        // closes the COM library on the current thread and unloads all DLLs loaded by the opposing thread
        // frees all other resources and forces all RPC connections to close
        CoUninitialize();

        return -1;
    }

    // obtain rough size
    size_t sizeGPO = sizeof(GLOBAL_PROFILER_OPTIONS) / sizeof(GLOBAL_PROFILER_OPTIONS[0]);

    // process cli
    for (int i = PROGRAM_ENTRY; i < argvCount; i++) // i = 1 to skip program name
    {
        if (wcscmp(argList[i], L"-h") == 0 || wcscmp(argList[i], L"--help") == 0)
        {
            ReturnHelpStatus();
        }

        // SHOW TARGET PROFILER WDF SUBLISTING
        else if (wcscmp(argList[i], L"-s") == 0 || wcscmp(argList[i], L"--show") == 0)
        {
            // check for TARGET PROFILER after "-s/--show". Ex: "-s/--show <TARGET PROFILER>"
            if (i + PROGRAM_ENTRY < argvCount)
            {
                wchar_t *target_profiler = argList[i + 1];
                wprintf(L"[*] SET TARGET PROFILER=\"%s\"\n\n", target_profiler);

                for (size_t x = 0; x < sizeGPO; x++)
                {
                    if (wcscmp(target_profiler, GLOBAL_PROFILER_OPTIONS[x]) == 0)
                    {
                        // repeat, repeat, repeat, repeat. I know. Try a switch statement.....Integral data types only
                       if (wcscmp(target_profiler, L"DOMAIN") == 0)
                        {
                            setCount += 1;
                            opt_no_quit = 0;

                            GetDomainProfilerStatus(pNetFwPolicy2, opt_no_quit);
                        }

                        else if (wcscmp(target_profiler, L"PRIVATE") == 0)
                        {
                            setCount += 1;
                            opt_no_quit = 0;

                            GetPrivateProfilerStatus(pNetFwPolicy2, opt_no_quit);
                        }

                        else if (wcscmp(target_profiler, L"PUBLIC") == 0)
                        {
                            setCount += 1;
                            opt_no_quit = 0;

                            GetPublicProfileStatus(pNetFwPolicy2, opt_no_quit);
                        }

                        else if (wcscmp(target_profiler, L"*") == 0 || wcscmp(target_profiler, L"ALL") == 0)
                        {
                            /*
                               the GetAllProfilerStatus target profiler function calls each ProfileStatus function helper individually
                               via setting opt_no_quit = 1; which tells the ProfileStatus function helpers to do nothing instead of calling "exit(0)"
                               which in turn passes execution back to main() without quitting the process such as when just calling a single profiler such as 
                               DOMAIN,PRIVATE,PUBLIC instead of ALL,* respectively
                            */
                            GetAllProfilerStatus(pNetFwPolicy2);
                        }

                        // 0xDEC (DEAD END CODE)
                    }

                    else
                    {
                        setCount += 1;

                        if (setCount == sizeGPO)
                        {
                            printf("** ILLEGAL TARGET PROFILER FOUND!\n");

                            return -1;
                        }

                        continue;
                    }

                    // 0xDEC (DEAD END CODE)
                }
                
                // 0xDEC (DEAD END CODE)
            }
            else 
                GRACEFUL_PROFILER_HANDLE
        }

        // DISABLE TARGET PROFILER WDF SUBLISTING
        else if (wcscmp(argList[i], L"-d") == 0 || wcscmp(argList[i], L"--disable") == 0)
        {
            LPWSTR *substring = &argList[i + 1]; // points to the address of the 2nd argument to firewallstatus starting from 0

            if (i + PROGRAM_ENTRY < argvCount)
            {
                wprintf(L"[+] SET TARGET PROFILER => \"%s\"\n[*] Calling intermediate Windows firewall helper function...\n\n", *substring); // dereference pointer above

                // check if supplemented profiler from user argument is contained within the global profiler options listing
                for (size_t x = 0; x < sizeGPO; x++) // re cast the same for loop as above when calling "show"
                {
                    // start check
                    if (wcscmp(*substring, GLOBAL_PROFILER_OPTIONS[x]) == 0)
                    {
                        // if the target profiler sublisting is an accepted parameter to the function then exit the for loop, else continue...
                        break;
                    }

                    else 
                    {
                        setCount += 1;

                        // failed to successfully extract an accepted targeted windows profiler sublisting (DOMAIN, PUBLIC, PRIVATE, ALL/*)
                        if (setCount == sizeGPO)
                        {
                            printf("** ILLEGAL TARGET PROFILER FOUND!\n");

                            return -1;
                        }

                        continue;
                    }
                }

                // send a generic "route request" to the global windows defender firewall manipulation helper function below
                HandleFwManipulationRequest(pNetFwPolicy2, substring, SET_FLAG_DISABLE);
            }
            else 
                GRACEFUL_PROFILER_HANDLE
        }
    
        // ENABLE TARGET PROFILER WDF SUBLISTING
        else if (wcscmp(argList[i], L"-e") == 0 || wcscmp(argList[i], L"--enable") == 0)
        {
            LPWSTR *substring = &argList[i + 1];

            if (i + PROGRAM_ENTRY < argvCount)
            {
                wprintf(L"[+] SET TARGET PROFILER => \"%s\"\n[*] Calling intermediate Windows firewall helper function...\n\n", *substring);

                for (size_t x = 0; x < sizeGPO; x++)
                {
                    if (wcscmp(*substring, GLOBAL_PROFILER_OPTIONS[x]) == 0)
                    {
                        break;
                    }

                    else 
                    {
                        setCount += 1;

                        if (setCount == sizeGPO)
                        {
                            printf("** ILLEGAL TARGET PROFILER FOUND!\n");

                            return -1;
                        }

                        continue;
                    }
                }

                HandleFwManipulationRequest(pNetFwPolicy2, substring, SET_FLAG_ENABLE);
            }
            else 
                GRACEFUL_PROFILER_HANDLE
        }

        // user entered option that is not declared yet in the total program scope (acceptable flags)
        else 
        {
            wprintf(L"Error: unrecognized argument \"%s\"\nINFO: use target \"-h/--help\" to display program usage information.\n", argList[i]);

            return -1;
        }
    
        // 0xDEC (DEAD END CODE)

        break;
    }

    printf("END\n");

    DISCARD_NETPOLICY_HANDLE;
    CoUninitialize();

    return 0;
}


void HandleFwManipulationRequest(INetFwPolicy2 *pNetFwPolicy2, LPWSTR *sublisting, int set_flag)
{
    switch (set_flag)
    {
        case SET_FLAG_DISABLE:
        {
            // handle disable
            DisableWindowsFirewall(pNetFwPolicy2, sublisting);
        }

        case SET_FLAG_ENABLE:
        {
            // handle enable
            EnableWindowsFirewall(pNetFwPolicy2, sublisting);
        }

        // undefined error boundary, created bogus exception handling
        default:
        {
            printf("How did you get here? Live debugging? Nasty.\n");
            exit(-1);
        }
    }
}


void DisableWindowsFirewall(INetFwPolicy2 *pNetFwPolicy2, LPWSTR *sublisting)
{
    int DISABLE_PROFILER_OP = 0;

    // block statement for code clarity when reading source code
    {
        if (wcscmp(*sublisting, L"DOMAIN") == 0)
            NETFWP2_CODE = 1;

        else if (wcscmp(*sublisting, L"PUBLIC") == 0) 
            NETFWP2_CODE = 2;
        
        else if (wcscmp(*sublisting, L"PRIVATE") == 0) 
            NETFWP2_CODE = 3;
        
        else if (wcscmp(*sublisting, L"ALL") == 0 || wcscmp(*sublisting, L"*") == 0) 
        {
            NETFWP2_CODE = PRIMITIVE_ALL_CHECK;
        }
    }
    
    switch (NETFWP2_CODE)
    {
        case NFWP2_DOMAIN:
        {
            // set option to target the DOMAIN profiler
            DISABLE_PROFILER_OP = NET_FW_PROFILE2_DOMAIN;
            printf("%s DOMAIN\n", PROFILER_STRING);

            break;
        }

        case NFWP2_PUBLIC:
        {
            // set option to target the PUBLIC profiler            
            DISABLE_PROFILER_OP = NET_FW_PROFILE2_PUBLIC;
            printf("%s PUBLIC\n", PROFILER_STRING);
            
            break;
        }

        case NFWP2_PRIVATE:
        {
            // set option to target the PRIVATE profiler  
            DISABLE_PROFILER_OP = NET_FW_PROFILE2_PRIVATE;
            printf("%s PRIVATE\n", PROFILER_STRING);

            break;
        }

        // all representations of the accepted target profiler sublistings are to be disabled
        case PRIMITIVE_ALL_CHECK:
        {
            // the optimal target must be provisioned to increase in its base integral value for each successful
            // manipulation operation against the target profiler
            int OPTIMAL_TARGET = 0; // 3 (DOMAIN, PUBLIC, PRIVATE)

            int NET_FW_PROFILERS[3] =
            {
                NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE2_PRIVATE                
            };

            wchar_t *TARGET_PROFILERS[3] = {L"DOMAIN", L"PUBLIC", L"PRIVATE"};

            do
            {   
                HRESULT disableWindowsFw = pNetFwPolicy2->lpVtbl->put_FirewallEnabled(pNetFwPolicy2, NET_FW_PROFILERS[OPTIMAL_TARGET], (VARIANT_BOOL)SET_FLAG_DISABLE);
            
                if (FAILED(disableWindowsFw))
                {
                    printf("%ls(%ls)%ls", RETURN_ERROR_DISABLE[0], TARGET_PROFILERS[OPTIMAL_TARGET], RETURN_ERROR_DISABLE[1]);

                    exit(0);
                }

                else if (SUCCEEDED(disableWindowsFw))
                {
                    printf("Disabled Windows Defender Firewall: (%ls)\n", TARGET_PROFILERS[OPTIMAL_TARGET]);
                }

                OPTIMAL_TARGET++;

            } while (OPTIMAL_TARGET != 3);

            DISCARD_NETPOLICY_HANDLE;
            CoUninitialize();

            exit(0);
        }

        case -1:
            exit(-1);
    }

    HRESULT disableWindowsFw = pNetFwPolicy2->lpVtbl->put_FirewallEnabled(pNetFwPolicy2, DISABLE_PROFILER_OP, (VARIANT_BOOL)SET_FLAG_DISABLE);

    if (FAILED(disableWindowsFw))
    {
        printf("%ls(%ls)%ls", RETURN_ERROR_DISABLE[0], *sublisting, RETURN_ERROR_DISABLE[1]);

        exit(0);
    }

    else if (SUCCEEDED(disableWindowsFw))
    {
        printf("==========================================================\n");
        printf("Successfully disabled the Windows Defender Firewall (%ls)\n", *sublisting);
        printf("==========================================================\n\n");
    }

    DISCARD_NETPOLICY_HANDLE;
    CoUninitialize();

    exit(0);
}


void EnableWindowsFirewall(INetFwPolicy2 *pNetFwPolicy2, LPWSTR *sublisting)
{
    int ENABLE_PROFILER_OP = 0;

    {
        if (wcscmp(*sublisting, L"DOMAIN") == 0)
            NETFWP2_CODE = 1;

        else if (wcscmp(*sublisting, L"PUBLIC") == 0) 
            NETFWP2_CODE = 2;
        
        else if (wcscmp(*sublisting, L"PRIVATE") == 0) 
            NETFWP2_CODE = 3;
        
        else if (wcscmp(*sublisting, L"ALL") == 0 || wcscmp(*sublisting, L"*") == 0) 
        {
            NETFWP2_CODE = PRIMITIVE_ALL_CHECK;
        }
    }
    
    switch (NETFWP2_CODE)
    {
        case NFWP2_DOMAIN:
        {
            // set option to target the DOMAIN profiler
            ENABLE_PROFILER_OP = NET_FW_PROFILE2_DOMAIN;
            printf("%s DOMAIN\n", PROFILER_STRING);

            break;
        }

        case NFWP2_PUBLIC:
        {
            // set option to target the PUBLIC profiler            
            ENABLE_PROFILER_OP = NET_FW_PROFILE2_PUBLIC;
            printf("%s PUBLIC\n", PROFILER_STRING);
            
            break;
        }

        case NFWP2_PRIVATE:
        {
            // set option to target the PRIVATE profiler  
            ENABLE_PROFILER_OP = NET_FW_PROFILE2_PRIVATE;
            printf("%s PRIVATE\n", PROFILER_STRING);

            break;
        }

        case PRIMITIVE_ALL_CHECK:
        {
            int OPTIMAL_TARGET = 0; // 3 (DOMAIN, PUBLIC, PRIVATE)

            int NET_FW_PROFILERS[3] =
            {
                NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE2_PRIVATE                
            };

            wchar_t *TARGET_PROFILERS[3] = {L"DOMAIN", L"PUBLIC", L"PRIVATE"};

            do
            {                
                HRESULT enableWindowsFw = pNetFwPolicy2->lpVtbl->put_FirewallEnabled(pNetFwPolicy2, NET_FW_PROFILERS[OPTIMAL_TARGET], (VARIANT_BOOL)SET_FLAG_ENABLE);
            
                if (FAILED(enableWindowsFw))
                {
                    printf("%ls(%ls)%ls", RETURN_ERROR_DISABLE[0], TARGET_PROFILERS[OPTIMAL_TARGET], RETURN_ERROR_DISABLE[1]);

                    exit(0);
                }

                else if (SUCCEEDED(enableWindowsFw))
                {
                    printf("Enabled Windows Defender Firewall: (%ls)\n", TARGET_PROFILERS[OPTIMAL_TARGET]);
                }

                OPTIMAL_TARGET++;

            } while (OPTIMAL_TARGET != 3);

            DISCARD_NETPOLICY_HANDLE;
            CoUninitialize();

            exit(0);
        }

        case -1:
            exit(-1);
    }

    HRESULT enableWindowsFw = pNetFwPolicy2->lpVtbl->put_FirewallEnabled(pNetFwPolicy2, ENABLE_PROFILER_OP, (VARIANT_BOOL)SET_FLAG_ENABLE);

    if (FAILED(enableWindowsFw))
    {
        printf("%ls(%ls)%ls", RETURN_ERROR_DISABLE[0], *sublisting, RETURN_ERROR_DISABLE[1]);

        exit(0);
    }

    else if (SUCCEEDED(enableWindowsFw))
    {
        printf("==========================================================\n");
        printf("Successfully enabled the Windows Defender Firewall (%ls)\n", *sublisting);
        printf("==========================================================\n\n");
    }

    DISCARD_NETPOLICY_HANDLE;
    CoUninitialize();

    exit(0); 
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++ EXPLICIT FUNCTION GROUPING START +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

void GetDomainProfilerStatus(INetFwPolicy2 *pNetFwPolicy2, int opt_no_quit)
{
    HRESULT pDomainProfiler;
    VARIANT_BOOL fwEnabledDomain; // is the target profiler active?

    pDomainProfiler = pNetFwPolicy2->lpVtbl->get_FirewallEnabled(pNetFwPolicy2, NET_FW_PROFILE2_DOMAIN, &fwEnabledDomain);

    switch (fwEnabledDomain)
    {
        case VARIANT_TRUE:
            printf("Firewall (DOMAIN): ACTIVE\n");

            break;

        case VARIANT_FALSE:
            printf("Firewall (DOMAIN): DISABLED\n");

            break;

        default:
            printf("Firewall (DOMAIN): UNKNOWN\n");

            break;
    }

    if (!opt_no_quit)
    {
        DISCARD_NETPOLICY_HANDLE;

        exit(0);
    }
    else 
    {
        ;
    }
}


void GetPrivateProfilerStatus(INetFwPolicy2 *pNetFwPolicy2, int opt_no_quit)
{
    HRESULT pPrivateProfiler;
    VARIANT_BOOL fwEnabledPrivate;

    pPrivateProfiler = pNetFwPolicy2->lpVtbl->get_FirewallEnabled(pNetFwPolicy2, NET_FW_PROFILE2_PRIVATE, &fwEnabledPrivate);

    switch (fwEnabledPrivate)
    {
        case VARIANT_TRUE:
            printf("Firewall (PRIVATE): ACTIVE\n");

            break;

        case VARIANT_FALSE:
            printf("Firewall (PRIVATE): DISABLED\n");

            break;

        default:
            printf("Firewall (PRIVATE): UNKNOWN\n");

            break;
    }

    if (!opt_no_quit)
    {
        DISCARD_NETPOLICY_HANDLE;

        exit(0);
    }
    else 
    {
        ;
    }
}


void GetPublicProfileStatus(INetFwPolicy2 *pNetFwPolicy2, int opt_no_quit)
{
    HRESULT pPublicProfiler;
    VARIANT_BOOL fwEnabledPublic;

    pPublicProfiler = pNetFwPolicy2->lpVtbl->get_FirewallEnabled(pNetFwPolicy2, NET_FW_PROFILE2_PUBLIC, &fwEnabledPublic);

    switch (fwEnabledPublic)
    {
        case VARIANT_TRUE:
            printf("Firewall (PUBLIC): ACTIVE\n");

            break;

        case VARIANT_FALSE:
            printf("Firewall (PUBLIC): DISABLED\n");

            break;

        default:
            printf("Firewall (PUBLIC): UNKNOWN\n");

            break;
    }

    if (!opt_no_quit) // if not set to 1, quit
    {
        DISCARD_NETPOLICY_HANDLE;

        exit(0);
    }
    else
    {
        ;
    }
}


void GetAllProfilerStatus(INetFwPolicy2 *pNetFwPolicy2)
{
    // set opt_no_quit to 1 as a "dummy" method of reusing each function
    // setting opt_no_quit to 1 passes function execution back to the calling function GetAllProfilerStatus()
    int opt_no_quit = 1;

    GetDomainProfilerStatus(pNetFwPolicy2, opt_no_quit);
    GetPrivateProfilerStatus(pNetFwPolicy2, opt_no_quit);
    GetPublicProfileStatus(pNetFwPolicy2, opt_no_quit);

    DISCARD_NETPOLICY_HANDLE;

    exit(0);
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++ EXPLICIT FUNCTION GROUPING END +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


void ReturnHelpStatus(void)
{
    char *help = "fwstatus - Microsoft Defender Firewall Status Operations";

    size_t help_size = strlen(help) + strlen(UTILITY_VERSION) + 1; // forget strcat

    printf("%s %s\n", help, UTILITY_VERSION);

    for (size_t i = 0; /*NULL*/; i++)
    {
        do {
            printf("=");

            break; // prevent infinite "=" execution loop

        } while (i <= help_size - 1);

        if (i == help_size - 1)
        {
            break;
        }
        else
            continue;
    }

    printf("\n\n");

    printf("HELP: <ARGS>\n============\n");
    printf("\t-h/--help\tshow the currently active \"help\" listing and exit\n");
    printf("\t-s/--show\tshow profiler status of MDF sublistings (DOMAIN, PRIVATE, PUBLIC, */ALL)\n");
    printf("\t-d/--disable\tdisable target MDF sublisting (DOMAIN, PRIVATE, PUBLIC, */ALL)\n");
    printf("\t-e/--enable\tenable target MDF sublisting (DOMAIN, PRIVATE, PUBLIC, */ALL)\n");

    exit(0);
}
#include <Windows.h>
#include <ShlObj.h>

#pragma comment(lib, "shell32.lib")

BOOL isProcessElevated(void);


int main(void)
{
    if (!isProcessElevated())
    {
        printf("This process is not running with elevated privileges!\n");
    }
    else 
    {
        printf("The current scope of the process contains elevated permissions!\n");
    }

    return 0;
}


BOOL isProcessElevated(void)
{
    BOOL isElevated = FALSE;
    
    if (!IsUserAnAdmin(&isElevated))
    {
        return FALSE;
    }

    return isElevated = TRUE;
}
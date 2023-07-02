# Fwstatus
Microsoft Defender Firewall Status Operations

This tool is responsible for manipulating the Windows Defender Firewall sublistings. Sublistings are directed as follows: the 3 "subsets" that exist directly underneath "Firewall & network protection". Fwstatus is able to directly access the Windows
Firewall "internally" by utilizing the Windows32 API.

Each of the 3 sublistings or "target profilers":
  * DOMAIN
  * PUBLIC
  * PRIVATE

can proactively be set to an enabled or disabled state.

This tool comes separately from an ongoing development suite of a "Windows Agent" that will be used to perform advanced operations and configuration to targeted machines that the "operator" has permission to interact with.

## Building
In order to use "fwstatus" you must have the included Windows development files installed to your local computer. These mandatory files are typically installed via Visual Studio.

Once you have verified that the proper components/libraries are installed to your local C drive, by confirming that the "Windows.h" header file is indeed importable via `#include <Windows.h` proceed as follows:
* `cl /EHsc /std:c11 firewallstatus.c /o fwstatus.exe`


## Usage:

![image](https://github.com/PlatinumVoyager/fwstatus/assets/116006542/9d6c31cc-40ee-4d5a-90b3-ef5270d3ae8a)

After completing the previous command to build to an executable, propagate the following commands to your list of actions needed to successfully run "fwstatus.exe":
1. `.\fwstatus.exe --help`
   - This will display ALL help information pertaining to manipulating the Windows Defender Firewall.

1. `.\fwstatus.exe -s/--show <DOMAIN, PUBLIC, PRIVATE, ALL/*>`
   - This will show the currently active profilers.

1. `.\fwstatus.exe -d/--disable <DOMAIN, PUBLIC, PRIVATE, ALL/*>`
   - Disable the current targeted profiler, or actively disable ALL Windows Defender Firewall sublistings.
  
1. `.\fwstatus.exe -e/--enable <DOMAIN, PUBLIC, PRIVATE, ALL/*>`
   - Enable the current targeted profiler, or actively enable ALL Windows Defender Firewall sublistings.
  
## Future Updates:
The current roadmap for a list of targeted features to support includes but is not limited to the following:
1. The ability to disable the Windows Defender Firewall notifications when a profiler is manipulated (enabled, disabled)
    - This will include the option to disable one or ALL available sublistings.
  

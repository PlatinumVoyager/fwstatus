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

# Building
In order to use "fwstatus" you must have the included Windows development files installed to you local computer. These mandatory files are typically installed via Visual Studio.

Once you have verified that the proper components/libraries are installed to your local C drive, by confirming that the "Windows.h" header file is indeed importable via `#include <Windows.h` proceed as follows:
* `cl /EHsc /std:c11 fwstatus.c /o fwstatus.exe`


## Usage:
``

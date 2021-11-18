# Bridge 1.0.10.0

Forked from: https://github.com/DroidOnUWP/Bridge

## Abstract
Another "Project Astoria" remake (UWP)

Original status: Forgotten (?)

## My actions (my 2 cents) 
1. Some research
2. Lite bugfix (some try...catch added to avoid accident app halts...)
3. Detected thet the code is not complete (Angle rendering not found).


## Description
- Android "bridge" for UWP applications, i.e. allows run Android Runtime as an UWP app....
- Note: This project was created as a proof-of-concept over a short amount of time.... 
- The code may not be perfect. It exists for demonstration and educational purposes.... 

## Coding "workbench"
1. Visual Studio 2022 (But VS 2017 compatibility remained, for Live WinPhone debugging, heh!)
2. CPP workloads added
3. Windows SDK 16053
4. Angle "library" (extension) must be...

## Some tech. details
- currently only ARM7 is supported (armeabi-v7a) 
- app does not work correctly - needs to do some more research and find way, that works under UWP !
- Android Runtime initializes, but than it crashes when launching app (?)
- Android 7.1.1 r13 is used (?)


## Project status
- phase 1 Intro/RnD +- 3 /100
- phase 2 Design - 
- phase 3 Tech. project -
- phase 4 Dev. project  -
- phase 5 Tests/Intro   -


# Build
1. Clone repo including submodules
2. Install Angle templates(run Angle\templates\install.bat).   
3. Open Angle solution (Angle\winrt\10\src\Angle.sln), choose target ARM (or Win32 for Desktop debugs)
4. rebuild it (this step needed for libGLESv2.lib generation)
4. Open Bridge.sln
5. Choose target ARM (or Win32 for Desktop debugs)
6. Build solution and try to debug it...
7. ...

## FAQ

Q: When debugging in Visual Studio Access violation exception occurs. How to fix it?

A: Uncheck "Break when this exception type is thrown", so FLinux exception handler can work correctly


## Contribute!
There's still a TON of things missing from this proof-of-concept (MVP) and areas of improvement 

With best wishes,

  [m][e] 2021

"Android Bridge" is RnD project only. AS-IS. No support. Distributed under the MIT License.


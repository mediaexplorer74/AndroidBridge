# BRIDGE: Android bridge for UWP applications

## About
The main goal is run Android Runtime as an UWP app.

## Project status
- phase 1 Intro/RnD +- 7 /100
- phase 2 Design - 
- phase 3 Tech. project -
- phase 4 Dev. project  -
- phase 5 Tests/Intro   -

## My 2 cents
- the attempt to fix mm (enlarge the memory heap...)
- fork does not work correctly - needs to do some more research and find way, that works under UWP
- Android Runtime initializes, but than it crashes when launching app
- Android 7.1.1 r13 is used
- Newest Visual Studio 2022 Preview used to RnD/remake some things :)

## HowTo Make Your Own Experiments
1. Clone this repo 
2. Install Angle templates(run Angle\templates\install.bat) and pre-build Angle solution 
   (start Angle\winrt\10\src\All.sln and compile all libs)
3. Open AB.sln
4. Choose "Win32" (x86) target, build and test it... 
5. Choose "ARM device" target, build and test it... 

## FAQ

Q: When debugging in Visual Studio Access violation exception occurs. How to fix it?

A: Try to uncheck "Break when this exception type is thrown", so FLinux exception handler can work correctly... (?)

## Thanks!
I wanted to put down some thank you's here for folks/projects/websites that were invaluable for helping me get this project into a functional state:
- [WallyCZ](https://github.com/WallyCZ) - (Android)Bridge project creator/author/developer.
- [Bridge](https://github.com/DroidOnUWP/Bridge) - Android bridge for UWP applications.
- [Microsoft](https://github.com/microsoft) - Thanx for all your open-source samples of your great code :)

## License & Copyright

MicroStore is RnD project. AS-IS. No support. Distributed under the MIT License. 

## Contribute!
There's still a TON of things missing from this proof-of-concept (MVP) and areas of improvement 

With best wishes,

  [m][e] 2022


"Android Bridge" is RnD project only. AS-IS. No support. Distributed under the MIT License.


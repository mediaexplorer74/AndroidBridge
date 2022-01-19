# BRIDGE: Android bridge for UWP applications
The main goal is run Android Runtime as an UWP app...

[![Build status](https://ci.appveyor.com/api/projects/status/h0a9b5qfy3rq4amf/branch/master?svg=true)](https://ci.appveyor.com/project/WallyCZ/bridge/branch/master)

[![Join the chat at https://gitter.im/DroidOnUWP/Bridge](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/DroidOnUWP/Bridge?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


# Status
- fork does not work correctly - needs to do some more research and find way, that works under UWP
- Android Runtime initializes, but than it crashes when launching app
- Android 7.1.1 r13 is used
- Newest Visual Studio 2022 Preview used to RnD/remake some things...

# How To Make Your Own Experiments
1. Clone this repo 
2. Install Angle templates (run Angle\templates\install.bat) and build Angle solution (Angle\winrt\10\gyp\All.sln) separately
3. Open AndroidBridge.sln
4. Choose target Win32 or ARM
5. Build and explore...
6. DIY...

-- me 2022
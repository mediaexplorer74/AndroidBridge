@echo OFF

REM ---------------------------------------------------------------------------------------------------------
REM Try to ensure the script is run from the right location
REM ---------------------------------------------------------------------------------------------------------
echo Check that this script is in the correct location
for %%a in (.) do set currentfolder=%%~na
IF %currentfolder% NEQ templates (
    echo    ERROR: Please run install.bat directly from the templates directory of your cloned/downloaded ANGLE repository.
    GOTO END
) else (
    echo    Script has been launched from a directory called templates.
)
REM ---------------------------------------------------------------------------------------------------------

REM ---------------------------------------------------------------------------------------------------------
REM Set the AngleRootPath system environment variable
REM ---------------------------------------------------------------------------------------------------------
echo Setting the 'AngleRootPath' system environment variable
echo    Setting AngleRootPath to "%~dp0.."

setx AngleRootPath "%~dp0.." > nul
IF %ERRORLEVEL% NEQ 0 ( 
    echo    ERROR: Unable to set AngleRootPath system environment variable; aborting.
    echo    See www.github.com/Microsoft/angle/wiki/installing-templates for manual installation steps.
    GOTO END
) else (
    echo    Successfully set AngleRootPath system environment variable.
)
REM ---------------------------------------------------------------------------------------------------------

REM ---------------------------------------------------------------------------------------------------------
REM Install Visual Studio 2022 templates
REM ---------------------------------------------------------------------------------------------------------
echo Installing ANGLE's Visual Studio 2022 templates

IF NOT EXIST "%userprofile%\Documents\Visual Studio 2022\Templates\ProjectTemplates" GOTO NOVS2022
echo    Visual Studio 2022 templates directory found

REM delete any old ANGLE templates
IF EXIST "%userprofile%\Documents\Visual Studio 2022\Templates\ProjectTemplates\Store Apps\Universal Apps\UniversalCoreWindow" (
echo    Removing old VS2022 UniversalCoreWindow template
@RD /S /Q "%userprofile%\Documents\Visual Studio 2022\Templates\ProjectTemplates\Store Apps\Universal Apps\UniversalCoreWindow"
)
IF EXIST "%userprofile%\Documents\Visual Studio 2022\Templates\ProjectTemplates\Store Apps\Universal Apps\UniversalSwapChainPanel" (
echo    Removing old VS2022 UniversalSwapChainPanel template
@RD /S /Q "%userprofile%\Documents\Visual Studio 2022\Templates\ProjectTemplates\Store Apps\Universal Apps\UniversalSwapChainPanel"
)
IF EXIST "%userprofile%\Documents\Visual Studio 2022\Templates\ProjectTemplates\Win32\DesktopHelloTriangle" (
echo    Removing old VS2013 DesktopHelloTriangle template
@RD /S /Q "%userprofile%\Documents\Visual Studio 2022\Templates\ProjectTemplates\Win32\DesktopHelloTriangle"
)

REM Install new templates
XCOPY "%~dp08.1" "%userprofile%\Documents\Visual Studio 2022\Templates\ProjectTemplates" /s /d /y > nul
IF %ERRORLEVEL% NEQ 0 ( 
    echo    Failed to install templates for Visual Studio 2022.
    echo    See www.github.com/Microsoft/angle/wiki/installing-templates for manual installation steps.
) ELSE (
    echo    Successfully installed latest Visual Studio 2022 templates.
)

GOTO ENDVS2022

:NOVS2022
echo    Visual Studio 2022 template directory not found. Skipped installing VS2013 templates.
:ENDVS2022
REM ---------------------------------------------------------------------------------------------------------

REM ---------------------------------------------------------------------------------------------------------
REM Install Visual Studio 2015 templates
REM ---------------------------------------------------------------------------------------------------------
echo Installing ANGLE's Visual Studio 2015 templates

IF NOT EXIST "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates" GOTO NOVS2015
echo    Visual Studio 2015 templates directory found

REM delete any old ANGLE templates
IF EXIST "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Windows\Windows Universal\CoreWindowUniversal" (
echo    Removing old VS2015 CoreWindowUniversal template
@RD /S /Q "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Windows\Windows Universal\CoreWindowUniversal"
)
IF EXIST "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Windows\Windows Universal\XamlUniversal" (
echo    Removing old VS2015 XamlUniversal template
@RD /S /Q "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Windows\Windows Universal\XamlUniversal"
)
IF EXIST "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Windows\Universal\CoreWindowUniversal" (
echo    Removing old VS2015 CoreWindowUniversal template
@RD /S /Q "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Windows\Universal\CoreWindowUniversal"
)
IF EXIST "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Windows\Universal\XamlUniversal" (
echo    Removing old VS2015 XamlUniversal template
@RD /S /Q "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Windows\Universal\XamlUniversal"
)

XCOPY "%~dp010" "%userprofile%\Documents\Visual Studio 2015\Templates\ProjectTemplates" /s /d /y > nul
IF %ERRORLEVEL% NEQ 0 ( 
    echo    Failed to install templates for Visual Studio 2015.
    echo    See www.github.com/Microsoft/angle/wiki/installing-templates for manual installation steps.
) ELSE (
    echo    Successfully installed latest Visual Studio 2015 templates.
)

GOTO ENDVS2015

:NOVS2015
echo    Visual Studio 2015 template directory not found. Skipped installing VS2015 templates.
:ENDVS2015
REM ---------------------------------------------------------------------------------------------------------

echo Script complete.
:END
pause
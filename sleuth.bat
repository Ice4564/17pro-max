@echo off
rem Runs Sleuth from its own folder, then returns the caller to where it was.
setlocal
pushd "%~dp0"
py -m sleuth %*
set "code=%ERRORLEVEL%"
popd
exit /b %code%

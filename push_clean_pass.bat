@echo off
setlocal
echo ========================================================
echo   Switching to CLEAN CODE (Triggering PASS Build)
echo ========================================================
echo.

cd /d "%~dp0"

copy /y tests\fixtures\hardened\app.py sample_app\app.py
copy /y tests\fixtures\hardened\requirements.txt sample_app\requirements.txt

git add sample_app\app.py sample_app\requirements.txt
git commit -m "fix: restore hardened sample application and patched dependencies"
echo Pushing clean code to GitHub...
git push origin main

echo.
echo ========================================================
echo   CLEAN CODE PUSHED!
echo   The Security Gate will now evaluate as:
echo   Evaluated by all scanners; PASS requires no HIGH or CRITICAL findings.
echo ========================================================
pause



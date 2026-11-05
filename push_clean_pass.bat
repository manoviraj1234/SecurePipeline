@echo off
setlocal
echo ========================================================
echo   Switching to CLEAN CODE (Triggering PASS Build)
echo ========================================================
echo.

cd /d "%~dp0"

copy /y sample_app\app_clean.py sample_app\app.py
copy /y sample_app\requirements_clean.txt sample_app\requirements.txt

git add sample_app\app.py sample_app\requirements.txt
git commit -m "fix: apply AI security recommendations to achieve clean PASS build"
echo Pushing clean code to GitHub...
git push origin main

echo.
echo ========================================================
echo   CLEAN CODE PUSHED!
echo   The Security Gate will now evaluate as:
echo   [PASS] DEPLOYMENT APPROVED (Green)
echo ========================================================
pause


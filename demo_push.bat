@echo off
setlocal
echo ========================================================
echo   SecurePipeline - Live Viva Push Demonstration
echo ========================================================
echo.

cd /d "%~dp0"

:: 1. Touch or update a live timestamp in sample_app/app.py
echo # Live viva demonstration timestamp: %date% %time% >> sample_app\app.py

:: 2. Stage the change
git add sample_app\app.py

:: 3. Commit with a timestamped message
git commit -m "demo: live security scan trigger [%date% %time%]"

:: 4. Push directly to GitHub
echo Pushing commit to GitHub repository...
git push origin main

echo.
echo ========================================================
echo   SUCCESS! Commit pushed to GitHub.
echo   Check your GitHub Actions tab:
echo   https://github.com/manoviraj1234/SecurePipeline/actions
echo ========================================================
pause


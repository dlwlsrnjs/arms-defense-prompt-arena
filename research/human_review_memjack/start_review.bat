@echo off
cd /d "%~dp0"
where py >nul 2>nul && (py -3 start_review.py %*) || (python start_review.py %*)
pause

@echo off
setlocal
cd /d "%~dp0"
echo Starting JARVIS local server...
echo Keep this window open while using JARVIS.
echo Open http://127.0.0.1:4700/ in your browser.
python server.py
pause

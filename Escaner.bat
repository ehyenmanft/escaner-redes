@echo off
rem Abre el escaner de red sin dejar una consola abierta. Debe estar junto a escaner_red.py
cd /d "%~dp0"
start "" pythonw escaner_red.py

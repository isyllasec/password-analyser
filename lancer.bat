@echo off
title Analyseur de mots de passe

echo Verification de Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo Python n'est pas installe sur votre machine.
    echo Telechargez-le sur https://www.python.org/downloads/
    echo Cochez bien "Add Python to PATH" lors de l'installation.
    echo.
    pause
    exit /b
)

if not exist "venv\" (
    echo Creation de l'environnement virtuel...
    python -m venv venv
)

echo Activation de l'environnement...
call venv\Scripts\activate.bat

echo Installation des dependances...
pip install -r requirements.txt --quiet

:MENU
echo.
echo ============================================
echo   Analyseur de mots de passe
echo ============================================
echo   1. Lancer la version web (navigateur)
echo   2. Lancer la version desktop (fenetre)
echo ============================================
echo.
set /p choix=Votre choix (1 ou 2) : 

if "%choix%"=="1" goto WEB
if "%choix%"=="2" goto DESKTOP
echo.
echo Choix invalide, merci de saisir 1 ou 2.
goto MENU

:WEB
echo.
echo Lancement de la version web...
streamlit run app.py
goto END

:DESKTOP
echo.
echo Lancement de la version desktop...
python app_desktop.py
goto END

:END
pause
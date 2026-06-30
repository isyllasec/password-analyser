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

echo Lancement de l'application...
streamlit run app.py

pause
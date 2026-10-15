@echo off
REM ============================================================
REM  IntrusionX dashboard - RESET FROM ZERO
REM  Put this file next to manage.py (the IntraX folder) and run it.
REM
REM  It will:
REM    1. Delete all migration files (keeps __init__.py)
REM    2. Delete db.sqlite3 (ALL companies, devices, alerts, blocks)
REM    3. Delete __pycache__ folders
REM    4. Recreate migrations, apply them, create admin/admin
REM
REM  Close runserver and any DB viewer first, or db.sqlite3
REM  cannot be deleted.
REM ============================================================

cd /d "%~dp0"

if not exist manage.py (
    echo ERROR: manage.py not found. Put this file in the IntraX folder.
    pause
    exit /b 1
)

echo.
echo WARNING: this deletes ALL data and ALL migrations.
set /p CONFIRM=Type YES to continue: 
if /i not "%CONFIRM%"=="YES" (
    echo Cancelled.
    pause
    exit /b 0
)

echo.
echo [1/5] Deleting migration files...
for %%A in (Entron EntronApi) do (
    if exist "%%A\migrations" (
        for %%F in ("%%A\migrations\0*.py") do del /q "%%F"
        if exist "%%A\migrations\__pycache__" rmdir /s /q "%%A\migrations\__pycache__"
        if not exist "%%A\migrations\__init__.py" type nul > "%%A\migrations\__init__.py"
    )
)

echo [2/5] Deleting database...
if exist db.sqlite3 del /q db.sqlite3
if exist db.sqlite3 (
    echo.
    echo ERROR: db.sqlite3 is locked by another process.
    echo Close runserver and any DB viewer, then run this again.
    pause
    exit /b 1
)

echo [3/5] Deleting __pycache__ folders...
for /d /r %%D in (__pycache__) do if exist "%%D" rmdir /s /q "%%D"

echo [4/5] Creating fresh migrations...
python manage.py makemigrations Entron
if errorlevel 1 goto :fail
python manage.py makemigrations EntronApi
if errorlevel 1 goto :fail

echo [5/5] Applying migrations and creating admin...
python manage.py migrate
if errorlevel 1 goto :fail
python manage.py create_admin
if errorlevel 1 goto :fail

echo.
echo ============================================================
echo  Done. Staff login: admin / admin
echo  Start the server with:  python manage.py runserver
echo ============================================================
pause
exit /b 0

:fail
echo.
echo ERROR: a step failed. Read the message above.
echo Make sure your venv is active and: pip install -r requirements.txt
pause
exit /b 1

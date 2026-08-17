@echo off
REM ============================================================
REM  Reset Entron / EntronApi migrations + DB for a clean test run
REM  Run this from: C:\Users\Admin\Downloads\Sameerprojects\IntrusionX\IntraX
REM
REM  IMPORTANT: close every other window/process touching this project
REM  first -- especially "python manage.py runserver" and any SQLite
REM  viewer/extension with db.sqlite3 open. If the file is locked, the
REM  delete below fails silently and you end up re-migrating into the
REM  SAME old database, which is why old devices/alerts can reappear
REM  even after "resetting".
REM ============================================================

echo Deleting Entron migrations (keeping __init__.py)...
for %%f in (Entron\migrations\0*.py) do del "%%f"
rmdir /s /q Entron\migrations\__pycache__ 2>nul

echo Deleting EntronApi migrations (keeping __init__.py)...
for %%f in (EntronApi\migrations\0*.py) do del "%%f"
rmdir /s /q EntronApi\migrations\__pycache__ 2>nul

echo Deleting sqlite DB...
del db.sqlite3 2>nul

if exist db.sqlite3 (
    echo.
    echo ============================================================
    echo  ERROR: db.sqlite3 is still here -- it's locked by another
    echo  process. Close runserver and any DB viewer, then run this
    echo  script again. Migrations were NOT reset.
    echo ============================================================
    pause
    exit /b 1
)

echo db.sqlite3 deleted successfully.

echo Regenerating migrations...
python manage.py makemigrations Entron
python manage.py makemigrations EntronApi

echo Applying migrations...
python manage.py migrate

echo.
echo Done. Now run: python manage.py createsuperuser
echo (needed to access /admin/ if that's how companies get created)
pause
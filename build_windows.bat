@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

rem =====================================================================
rem  Сборка TelegramProxyScanner.exe.
rem  Скрипт сам проверяет, что уже установлено, и устанавливает только то,
rem  чего не хватает - при повторном запуске ничего лишнего не скачивает.
rem  Если на компьютере вообще нет Python - объясняет это понятно и
rem  предлагает сразу открыть страницу загрузки, вместо непонятной ошибки
rem  "python is not recognized...".
rem =====================================================================

echo Проверка Python...
set "PY="

for %%C in (py python) do (
    if not defined PY (
        where %%C >nul 2>nul
        if not errorlevel 1 (
            rem Мало того что команда найдена в PATH - проверяем, что она и правда
            rem запускает Python, а не заглушку Microsoft Store - у таких "python.exe"
            rem есть в PATH, но реального Python за ними нет.
            %%C --version >nul 2>nul
            if not errorlevel 1 set "PY=%%C"
        )
    )
)

if not defined PY (
    echo.
    echo Python на этом компьютере не найден.
    echo.
    echo Программе нужен Python 3.9 или новее - это бесплатно и ставится за
    echo пару минут: https://www.python.org/downloads/
    echo На первом экране установщика ОБЯЗАТЕЛЬНО отметьте галочку внизу
    echo "Add python.exe to PATH" - без неё Windows не найдёт Python.
    echo.
    choice /M "Открыть страницу загрузки Python в браузере прямо сейчас"
    if not errorlevel 2 start "" "https://www.python.org/downloads/"
    echo.
    echo После установки Python запустите этот файл ^(build_windows.bat^) ещё раз.
    pause
    exit /b 1
)

echo Найден Python:
%PY% --version

echo.
echo Проверка зависимостей...

%PY% -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo   PyInstaller не найден - устанавливаю...
    %PY% -m pip install --upgrade pip >nul 2>nul
    %PY% -m pip install pyinstaller
    if errorlevel 1 goto :pip_error
) else (
    echo   PyInstaller уже установлен - пропускаю.
)

%PY% -c "import cryptography" >nul 2>nul
if errorlevel 1 (
    echo   cryptography не найден - устанавливаю...
    %PY% -m pip install cryptography
    if errorlevel 1 goto :pip_error
) else (
    echo   cryptography уже установлен - пропускаю.
)

%PY% -c "import telethon" >nul 2>nul
if errorlevel 1 (
    echo   telethon не найден - устанавливаю ^(чтение тг-каналов через MTProto^)...
    %PY% -m pip install telethon
    if errorlevel 1 goto :pip_error
) else (
    echo   telethon уже установлен - пропускаю.
)

%PY% -c "import PIL" >nul 2>nul
if errorlevel 1 (
    echo   Pillow не найден - устанавливаю ^(нужен для значков на кнопках^)...
    %PY% -m pip install pillow
    if errorlevel 1 goto :pip_error
) else (
    echo   Pillow уже установлен - пропускаю.
)

echo.
echo Сборка TelegramProxyScanner.exe ...
%PY% -m PyInstaller --noconfirm --onefile --windowed --collect-submodules telethon --hidden-import pyaes --hidden-import rsa --name TelegramProxyScanner TelegramProxyScanner.pyw
if errorlevel 1 goto :build_error

copy /Y dist\TelegramProxyScanner.exe . >nul
echo.
echo Готово: TelegramProxyScanner.exe
echo Пакеты cryptography, Pillow и telethon вшиты прямо в .exe (быстрая проверка
echo прокси, значки на кнопках, чтение тг-каналов) - отдельно их устанавливать не нужно.
pause
exit /b 0

:pip_error
echo.
echo ОШИБКА: не удалось установить зависимости через "%PY%".
echo Проверьте подключение к интернету и повторите запуск файла.
pause
exit /b 1

:build_error
echo.
echo ОШИБКА: сборка PyInstaller не удалась. Смотрите сообщения выше -
echo чаще всего это нехватка места на диске либо антивирус, временно
echo блокирующий PyInstaller.
pause
exit /b 1

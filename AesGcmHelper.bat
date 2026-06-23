@echo off
chcp 65001 > nul
cls
echo ==================================================
echo         AES-256-GCM Cryptography Helper
echo ==================================================
echo.

:menu
echo เลือกฟังก์ชันการทำงาน:
echo [1] เข้ารหัสข้อความ (Encrypt Text)
echo [2] ถอดรหัสข้อความ (Decrypt Text)
echo [3] เข้ารหัสไฟล์ทีละบรรทัด (Encrypt File Line-by-Line)
echo [4] ถอดรหัสไฟล์ทีละบรรทัด (Decrypt File Line-by-Line)
echo [5] ออกจากโปรแกรม (Exit)
echo.
set /p choice="ใส่ตัวเลขเลือกเมนู (1-5): "

if "%choice%"=="1" goto encrypt
if "%choice%"=="2" goto decrypt
if "%choice%"=="3" goto encrypt_file
if "%choice%"=="4" goto decrypt_file
if "%choice%"=="5" exit
cls
goto menu

:encrypt
echo.
echo --------------------------------------------------
echo [เข้ารหัสข้อความ]
echo --------------------------------------------------
set /p key="1. วางคีย์ (Hex หรือ Base64): "
set /p plaintext="2. วางข้อความที่ต้องการเข้ารหัส: "
echo.
echo กำลังเข้ารหัส...
echo ผลลัพธ์:
powershell -ExecutionPolicy Bypass -File "E:\AesGcmCrypto.ps1" -Action Encrypt -Key "%key%" -Text "%plaintext%"
echo --------------------------------------------------
echo.
pause
cls
goto menu

:decrypt
echo.
echo --------------------------------------------------
echo [ถอดรหัสข้อความ]
echo --------------------------------------------------
set /p key="1. วางคีย์ (Hex หรือ Base64): "
set /p ciphertext="2. วางข้อความเข้ารหัส (Base64): "
echo.
echo กำลังถอดรหัส...
echo ผลลัพธ์:
powershell -ExecutionPolicy Bypass -File "E:\AesGcmCrypto.ps1" -Action Decrypt -Key "%key%" -Text "%ciphertext%"
echo --------------------------------------------------
echo.
pause
cls
goto menu

:encrypt_file
echo.
echo --------------------------------------------------
echo [เข้ารหัสไฟล์ทีละบรรทัด]
echo --------------------------------------------------
set /p key="1. วางคีย์ (Hex หรือ Base64): "
set /p source="2. วางเส้นทางไฟล์ต้นทาง (เช่น E:\citizen_id.txt): "
set /p dest="3. วางเส้นทางไฟล์ปลายทาง (เช่น E:\citizen_id_enc.txt): "
echo.
echo กำลังเข้ารหัสไฟล์ทีละบรรทัด...
powershell -ExecutionPolicy Bypass -File "E:\AesGcmCrypto.ps1" -Action Encrypt -Key "%key%" -SourcePath "%source%" -DestinationPath "%dest%" -LineByLine
echo --------------------------------------------------
echo.
pause
cls
goto menu

:decrypt_file
echo.
echo --------------------------------------------------
echo [ถอดรหัสไฟล์ทีละบรรทัด]
echo --------------------------------------------------
set /p key="1. วางคีย์ (Hex หรือ Base64): "
set /p source="2. วางเส้นทางไฟล์ต้นทาง (เช่น E:\citizen_id_enc.txt): "
set /p dest="3. วางเส้นทางไฟล์ปลายทาง (เช่น E:\citizen_id_dec.txt): "
echo.
echo กำลังถอดรหัสไฟล์ทีละบรรทัด...
powershell -ExecutionPolicy Bypass -File "E:\AesGcmCrypto.ps1" -Action Decrypt -Key "%key%" -SourcePath "%source%" -DestinationPath "%dest%" -LineByLine
echo --------------------------------------------------
echo.
pause
cls
goto menu

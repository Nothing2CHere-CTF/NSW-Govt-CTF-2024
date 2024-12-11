# Steg Challenge

## I HATE ADS!

### Category:
Steg

### Challenge:
I HATE ADS SOO MUCH!  You know, I reckon everyone should use something like uBlock Origin by gorhill!

Anyway, I bet you can't find where I keep my super sensitive secret!

### Attachment:
secrets.7z

### Steps:
1. Extract the 7zip archive
2. Identify vmdk file as VMware disk file
3. Given the BitLocker Recovery Key file, spin up a Windows VM in VMware and attach disk
(steg/iha1.png)
4. Enter recovery key to unlock drive
(steg/iha2.png)
5. Open file location
(steg/iha3.png)
6. View secrets.txt
(steg/iha4.png)
7. Open location in PowerShell
8. Check for streams in secrets.txt
```powershell
Get-Item .\secrets.txt -Stream *
```
(steg/iha5.png)
9. Read secrets.txt:flag.txt to get flag
```powershell
Get-Content .\secrets.txt -Stream flag.txt
```
(steg/iha6.png)

### Flag:
`flag{d0n7_st0r3_sens!t!ve_inf0_in_@lternate_dat@_s7r3am5}`
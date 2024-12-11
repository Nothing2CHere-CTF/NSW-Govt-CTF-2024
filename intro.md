# Intro Challenges

## Welcome to Packet Analysis

### Category:
Intro

### Challenge Text:
Welcome to packet analysis :)

All you have to do is find the flag!

### Attachment:
pcap_intro.7z

### Steps:
1. Extract the 7zip archive
2. Open the PCAP file
3. Review the packets
4. Follow TCP stream
(intro/wtpa1.png)
5. Identify flag
(intro/wtpa2.png)

### Flag:
`flag{w3lc0me_to_w1re$harK}`


## FTP is secure, right?

### Category:
Intro

### Challenge:
I'm pretty sure someone told me FTP is secure, so I'm sure it's safe to store my flags on my FTP server.

### Attachment:
ftp.7z

### Steps:
1. Extract the 7zip archive
2. Open the PCAP file
3. Review the packets
4. Follow TCP stream
5. Identify username and password
(intro/ftp1.png)
6. Scroll through streams
7. Find stream where flag.zip is listed, and identify hint for file password
(intro/ftp2.png)
8. Export flag.zip
(intro/ftp3.png)
(intro/ftp4.png)
9. Extract zip file and read flag.txt
(intro/ftp5.png)

### Flag:
`flag{will_they_see_if_I_download_this?}`


## Simple Web Logs

### Category:
Intro

### Challenge:
We have pulled a couple of lines from an apache web access log file for you to investigate.  It appears an attacker tried to authenticate to the server with a weird string, and then a few minutes later there was a strange request.  Is there any way you can tell me whose account they tried to authenticate against, what they tried to do against the server, and if it was successful?

>192.168.177.130 - - [23/Nov/2024:16:52:43 +0000] "GET /?auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0IjoiSGFjayB0aGUgUGxhbmV0IiwibmFtZSI6IkNyYXNoIE92ZXJyaWRlIiwiaWF0IjoxNTE2MjM5MDIyfQ.EVSNKp9ZZQoSTLnPtzY-_Rjpbu_zkMV5OOJ0Szpxz5o HTTP/1.1" 200 89

>192.168.177.130 - - [23/Nov/2024:16:57:02 +0000] "GET /webshell.php?cmd=cat%20%2fetc%2fpasswd HTTP/1.1" 200 3978

### Flag Format: flag{FirstName LastName_command_yes/no} e.g. flag{Donald Trump_echo flag > /dev/shm/test_no}

### Steps:
1. Copy auth token to CyberChef
2. Click Magic button
(intro/swl1.png)
3. Identify name
(intro/swl2.png)
4. Copy webshell GET request to CyberChef
5. URL Decode input
(intro/swl3.png)
6. Identify original command
7. Google 200 HTTP status code.  Confirm request was successful, and bytes returned was indicative of /etc/passwd file size
8. Put name, command, success together to get flag  

### Flag:
`flag{Crash Override_cat /etc/passwd_yes}`


## More Web Logs

### Category:
Intro

### Challenge:
We have pulled some logs from one of our wesbites for you to check.  Are you able to advise if the attacker was able to locate any sensitive files and, if so, what file, and what they used to retrieve it?

### Flag Format: flag{file_program} e.g. flag{flag.txt_Firefox}

### Attachment:
access.7z

### Steps:
1. Extract the 7zip archive
2. Grep for 200 in the log file and output to new file
(intro/mwl1.png)
3. Or grep inverse for 403/404 in log file
(intro/mwl2.png)
4. Open new file
5. Find correct line among the 200 results
(intro/mwl3.png)
6. Note that "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" is the same user agent string for all the 400 results, indicating that this was probably not the program used to download the file, but instead a directory bruteforcer (in this case, that of *dirb*)
7. Combine filename and program as flag

### Flag:
`flag{backups_wget}`


## Check out my awesome project!

### Category:
Intro

### Challenge:
You're going to love my awesome new project!  Feel free to contribute to it, and together we will all make the world a better place 🌍

https://github.com/Nothing2CHere-CTF/myawesomeproject

### Steps:
1. Visit site
2. Note number of Commits
(intro/map1.png)
3. Click on Commits
(intro/map2.png)
4. Traverse the different commits using the hint given on the main page
(intro/map3.png)

### Flag:
`flag{1nce_c0mmi7ted_@lways_committ3d}`
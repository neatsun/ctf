# ctf
# this page does not represents my employer's opinions and is not related to any employer 
ctf prep 


oracle's virtual box http://www.oracle.com/technetwork/server-storage/virtualbox/downloads/index.html
   *** see https://www.virtualbox.org/manual/ch06.html#network_nat_service  for data on NAT Network 
ubuntu  https://www.ubuntu.com/download/desktop/thank-you?version=16.04.1&architecture=amd64

kali linux - http://www.kali.org/downloads/ or https://www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/ (u: root p:toor)

minigw :http://www.mingw.org/

IDA  - https://www.hex-rays.com/products/ida/support/download_demo.shtml 

.net reflector http://www.red-gate.com/dynamic/products/dotnet-development/reflector/download

python  https://www.python.org/downloads/

sysinternals https://technet.microsoft.com/en-us/sysinternals/bb896653

cygwin https://cygwin.com/install.html

wireshark https://www.wireshark.org/#download

x64 debuger http://x64dbg.com/#start

metaspoit https://www.rapid7.com/products/metasploit/download.jsp

nmap https://nmap.org/download.html

winscp https://winscp.net/eng/download.php

burp [Web proxy like fiddler with active abilities ] http://portswigger.net/burp/proxy.html

-- IDE --------

Pycharm https://www.jetbrains.com/pycharm/download/

sublime  https://www.sublimetext.com/3

---------usefull ------

tmux - multi screen terminal cheat sheet  https://gist.github.com/MohamedAlaa/2961058

socat - run python sript on incoming tcp / serial connection http://technostuff.blogspot.co.il/2008/10/some-useful-socat-commands.html

AFL (american fuzzy lop) - http://lcamtuf.coredump.cx/afl/

strings - shows strings in ELF file 

-disposable email  https://www.guerrillamail.com/  - temp email 


--- backdoors &shells --------

backdoor factory: https://github.com/secretsquirrel/the-backdoor-factory

shell code home page : http://shell-storm.org/shellcode/


-------- WEb -------------

Burp -   https://portswigger.net/burp/download.html

Proxy changer plugin https://chrome.google.com/webstore/detail/proxy-switchysharp/dpplabbmogkhghncfbfdeeokoefdjegm?hl=en

fiddler  - https://www.telerik.com/download/fiddler


---------------------THP2----------------------------------- dup from  cheetz's git hub page  for ease
The Hacker Playbook 2
http://www.amazon.com/dp/1512214566/

Once Your Kali VM is Up and Running
●	Setup Metasploit database
	○	service postgresql start
●	Make postgresql database start on boot
	○	update-rc.d postgresql enable
●	Start and stop the Metasploit service (this will setup the database.yml file for you)
	○	service metasploit start
	○	service metasploit stop
●	Install gedit
	○	apt-get install gedit
●	Change the hostname - Many network admins look for systems named Kali in logs like DHCP. It is best to follow the naming standard used by the company you are testing
	○	gedit /etc/hostname
		■	Change the hostname (replace kali) and save
	○	gedit /etc/hosts
		■	Change the hostname (replace kali) and save
	○	reboot
●	*Optional for Metasploit - Enable Logging
	○	I list this as optional since logs get pretty big, but you have the ability to log every command and result from Metasploit’s Command Line Interface (CLI). This becomes very useful for bulk attack/queries or if your client requires these logs. *If this is a fresh image, type msfconsole first and exit before configuring logging to create the .msf4 folder.
	○	From a command prompt, type:
		■	echo “spool /root/msf_console.log” > /root/.msf4/msfconsole.rc
	○	Logs will be stored at /root/msf_console.log

Tool Installation
The Backdoor Factory:
●	Patch PE, ELF, Mach-O binaries with shellcode.
●	git clone https://github.com/secretsquirrel/the-backdoor-factory /opt/the-backdoor-factory
●	cd the-backdoor-factory
●	./install.sh

HTTPScreenShot
●	HTTPScreenshot is a tool for grabbing screenshots and HTML of large numbers of websites.
●	pip install selenium
●	git clone https://github.com/breenmachine/httpscreenshot.git /opt/httpscreenshot
●	cd /opt/httpscreenshot
●	chmod +x install-dependencies.sh && ./install-dependencies.sh
●	HTTPScreenShot only works if you are running on a 64-bit Kali by default. If you are running 32-bit PAE, install i686 phatomjs as follows:
	○	wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-1.9.8-linux-i686.tar.bz2
	○	bzip2 -d phantomjs-1.9.8-linux-i686.tar.bz2
	○	tar xvf phantomjs-1.9.8-linux-i686.tar
	○	cp phantomjs-1.9.8-linux-i686/bin/phantomjs /usr/bin/

SMBExec
●	A rapid psexec style attack with samba tools.
●	git clone https://github.com/pentestgeek/smbexec.git /opt/smbexec
●	cd /opt/smbexec && ./install.sh
●	Select 1 - Debian/Ubuntu and derivatives
●	Select all defaults
●	./install.sh
●	Select 4 to compile smbexec binaries
●	After compilation, select 5 to exit
Masscan
●	This is the fastest Internet port scanner. It can scan the entire Internet in under six minutes.
●	apt-get install git gcc make libpcap-dev
●	git clone https://github.com/robertdavidgraham/masscan.git /opt/masscan
●	cd /opt/masscan
●	make
●	make install

Gitrob
●	Reconnaissance tool for GitHub organizations
●	git clone https://github.com/michenriksen/gitrob.git /opt/gitrob
●	gem install bundler
●	service postgresql start
●	su postgres
●	createuser -s gitrob --pwprompt
●	createdb -O gitrob gitrob
●	exit
●	cd /opt/gitrob/bin
●	gem install gitrob

CMSmap
●	CMSmap is a python open source CMS (Content Management System) scanner that automates the process of detecting security flaws
●	git clone https://github.com/Dionach/CMSmap /opt/CMSmap

WPScan
●	WordPress vulnerability scanner and brute-force tool
●	git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
●	cd /opt/wpscan && ./wpscan.rb --update

Eyewitness
●	EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
●	git clone https://github.com/ChrisTruncer/EyeWitness.git /opt/EyeWitness

Printer Exploits
●	Contains a number of commonly found printer exploits
●	git clone https://github.com/MooseDojo/praedasploit /opt/praedasploit

SQLMap
------
	SQL Injection tool
	git clone https://github.com/sqlmapproject/sqlmap /opt/sqlmap
u can user with cookie   by adding --cookie="birthday_invite=1234"

Recon-ng
●	A full-featured web reconnaissance framework written in Python
●	git clone https://bitbucket.org/LaNMaSteR53/recon-ng.git /opt/recon-ng

Discover Scripts
●	Custom bash scripts used to automate various pentesting tasks.
●	git clone https://github.com/leebaird/discover.git /opt/discover
●	cd /opt/discover && ./update.sh

BeEF Exploitation Framework
●	A cross-site scripting attack framework
●	cd /opt/
●	wget https://raw.github.com/beefproject/beef/a6a7536e/install-beef
●	chmod +x install-beef
●	./install-beef

Responder
●	A LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication. Responder will be used to gain NTLM challenge/response hashes
●	git clone https://github.com/SpiderLabs/Responder.git /opt/Responder

The Hacker Playbook 2 - Custom Scripts
●	A number of custom scripts written by myself for The Hacker Playbook 2.
●	git clone https://github.com/cheetz/Easy-P.git /opt/Easy-P
●	git clone https://github.com/cheetz/Password_Plus_One /opt/Password_Plus_One
●	git clone https://github.com/cheetz/PowerShell_Popup /opt/PowerShell_Popup
●	git clone https://github.com/cheetz/icmpshock /opt/icmpshock
●	git clone https://github.com/cheetz/brutescrape /opt/brutescrape
●	git clone https://www.github.com/cheetz/reddit_xss /opt/reddit_xss

The Hacker Playbook 2 - Forked Versions
●	Forked versions of PowerSploit and Powertools used in the book. Make sure you clone your own repositories from the original sources.
●	git clone https://github.com/cheetz/PowerSploit /opt/HP_PowerSploit
●	git clone https://github.com/cheetz/PowerTools /opt/HP_PowerTools
●	git clone https://github.com/cheetz/nishang /opt/nishang

DSHashes:
●	Extracts user hashes in a user-friendly format for NTDSXtract
●	wget http://ptscripts.googlecode.com/svn/trunk/dshashes.py -O /opt/NTDSXtract/dshashes.py

SPARTA:
●	A python GUI application which simplifies network infrastructure penetration testing by aiding the penetration tester in the scanning and enumeration phase.
●	git clone https://github.com/secforce/sparta.git /opt/sparta
●	apt-get install python-elixir
●	apt-get install ldap-utils rwho rsh-client x11-apps finger

NoSQLMap
●	A automated pentesting toolset for MongoDB database servers and web applications.
●	git clone https://github.com/tcstool/NoSQLMap.git /opt/NoSQLMap

Spiderfoot
●	Open Source Footprinting Tool
●	mkdir /opt/spiderfoot/ && cd /opt/spiderfoot
●	wget http://sourceforge.net/projects/spiderfoot/files/spiderfoot-2.3.0-src.tar.gz/download
●	tar xzvf download
●	pip install lxml
●	pip install netaddr
●	pip install M2Crypto
●	pip install cherrypy
●	pip install mako


WCE
●	Windows Credential Editor (WCE) is used to pull passwords from memory
●	Download from: http://www.ampliasecurity.com/research/windows-credentials-editor/ and save to /opt/. For example:
	○	wget www.ampliasecurity.com/research/wce_v1_4beta_universal.zip
	○	mkdir /opt/wce && unzip wce_v1* -d /opt/wce && rm wce_v1*.zip

Mimikatz
●	Used for pulling cleartext passwords from memory, Golden Ticket, skeleton key and more
●	Grab the newest release from https://github.com/gentilkiwi/mimikatz/releases/latest
	○	cd /opt/ && wget http://blog.gentilkiwi.com/downloads/mimikatz_trunk.zip
	○	unzip -d ./mimikatz mimikatz_trunk.zip

SET
●	Social Engineering Toolkit (SET) will be used for the social engineering campaigns
●	git clone https://github.com/trustedsec/social-engineer-toolkit/ /opt/set/
●	cd /opt/set && ./setup.py install

PowerSploit (PowerShell)
●	PowerShell scripts for post exploitation
●	git clone https://github.com/mattifestation/PowerSploit.git /opt/PowerSploit
●	cd /opt/PowerSploit && wget https://raw.githubusercontent.com/obscuresec/random/master/StartListener.py && wget https://raw.githubusercontent.com/darkoperator/powershell_scripts/master/ps_encoder.py

Nishang (PowerShell)
●	Collection of PowerShell scripts for exploitation and post exploitation
●	git clone https://github.com/samratashok/nishang /opt/nishang

Veil-Framework
●	A red team toolkit focused on evading detection. It currently contains Veil-Evasion for generating AV-evading payloads, Veil-Catapult for delivering them to targets, and Veil-PowerView for gaining situational awareness on Windows domains. Veil will be used to create a python based Meterpreter executable.
●	git clone https://github.com/Veil-Framework/Veil /opt/Veil
●	cd /opt/Veil/ && ./Install.sh -c

ZAP Proxy Pro
●	OWASP ZAP: An easy-to-use integrated penetration testing tool for discovering vulnerabilities in web applications.
●	Download from: https://code.google.com/p/zaproxy/wiki/Downloads?tm=2
●	*Included by default in Kali Linux (owasp-zap)

Fuzzing Lists (SecLists)
●	These are scripts to use with Burp to fuzz parameters
●	git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists

Password Lists
●	For the different password lists, see the section: Special Teams - Cracking, Exploits, and Tricks

Net-Creds Network Parsing 
●	Parse PCAP files for username/passwords
●	git clone https://github.com/DanMcInerney/net-creds.git /opt/net-creds

Installing Firefox Add-ons
●	Web Developer Add-on: https://addons.mozilla.org/en-US/firefox/addon/web-developer/
●	Tamper Data: https://addons.mozilla.org/en-US/firefox/addon/tamper-data/
●	Foxy Proxy: https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
●	User Agent Switcher: https://addons.mozilla.org/en-US/firefox/addon/user-agent-switcher/

Wifite
●	Attacks against WiFi networks
●	git clone https://github.com/derv82/wifite /opt/wifite

WIFIPhisher
●	Automated phishing attacks against WiFi networks
●	git clone https://github.com/sophron/wifiphisher.git /opt/wifiphisher

Phishing (Optional):
●	Phishing-Frenzy
	○	git clone https://github.com/pentestgeek/phishing-frenzy.git /var/www/phishing-frenzy
●	Custom List of Extras
	○	git clone https://github.com/macubergeek/gitlist.git /opt/gitlist


-------------- end of THP2 -----------

-----ELF---------
readelf is a Unix binary utility that displays information about one or more ELF files. A free software implementation is provided by GNU Binutils.

elfutils ( need to apt-get elfutils ) provides alternative tools to GNU Binutils purely for Linux. (https://sourceware.org/elfutils/)

elfdump is a command for viewing ELF information in an ELF file, available under Solaris and FreeBSD.

objdump provides a wide range of information about ELF files and other object formats. objdump uses the Binary File Descriptor library as a back-end to structure the ELF data.

The Unix file utility can display some information about ELF files, including the instruction set architecture for which the code in a relocatable, executable, or shared object file is intended, or on which an ELF core dump was produced.


-- SOCAT ------- raise your own network server by running a local software [ note the EXEC param] 
sudo socat TCP-LISTEN:80,reuseaddr,fork EXEC:"./chroot",su=bender,echo=0,pty,stderr


PYTHON PWN FRAMEWORK http://docs.pwntools.com/en/stable/intro.html


--- wireshark add private key https://blogs.technet.microsoft.com/nettracer/2013/10/12/decrypting-ssltls-sessions-with-wireshark-reloaded/  = NOTE : u can set server ip to *.*.*.* 


-- web content management fingerprinting https://github.com/jekyc/wig

-- code flow solver https://github.com/angr/angr

-- linux PIE and NX file checker http://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/

--online disassembler - https://retdec.com ( including MIPS)

-- pgp on ubuntu guide --- https://www.deepdotweb.com/2015/02/17/basic-guide-pgp-linux/   [ gpg  --decrypt  filename.txt.gpg]
-- gdb-peda -- https://github.com/longld/peda -- Enhance the display of gdb: colorize and display disassembly codes, registers, memory information during debugging
-- root-me -- https://www.root-me.org
-- exploit pattern -- https://github.com/Svenito/exploit-pattern

--- binn walk forensics https://github.com/devttys0/binwalk

explenation on how calling functions actuallly work https://www.cs.princeton.edu/courses/archive/spring11/cos217/lectures/15AssemblyFunctions.pdf
http://www.cs.nyu.edu/courses/fall04/V22.0201-003/ia32_chap_03.pdf


ASM OPCODES  http://www.mathemainzel.info/files/x86asmref.html#jne


anti reversing explained https://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide



About 5gtop
===========

This program monitors the signal performance of Huawei 4G/5G modems.
It uses the Salamek huawei-lte API, and is written in Python 3.
See https://github.com/Salamek/huawei-lte-api

It should support all Huawei modems listed by Salamek.
But it has only been tested on an H112-372  5G CPE Pro and the N5368X 5G Outdoor CPE

It needs to know whether a 4G or 5G modem is in use.
This must be specified on the command line
using the -g switch, either -g 4 or -g 5. If not specified
it defaults to 5G.

In its default mode this program queries the modem once per second to retrieve the following
pieces of information:

1) Up time since last power on or reboot.  
2) Ping time in milliseconds. The host address to be pinged must be specified on the command line.  
3) Signal strength in bars, familiar to users of smartphones. It is a little optimistic.  
4) RSRP, reference signal receive power in dBm. This is the most useful value.  
5) RSRQ, reference signal receive quality in dB.  
6) SINR, signal to noise ratio in dB.

These values are also shown as a bar graph and colour coded to show an estimate
of whether these values are 

  * Blue  - excellent,
  * Green - good, 
  * Amber - adequate (mid-cell) or 
  * Red   - poor (edge-cell).

See https://www.digi.com/support/knowledge-base/understanding-lte-signal-strength-values

7)  Download speed in Mbit/sec.  
8)  Upload speed in Mbit/sec  
9)  Data used this month in Gbyte  
10) Data used today in Mbyte.

This data is stored in a log file 'signal-log.txt' and a new log file is created for each day.

The data for the current log can be viewed by typing 's' while in the program.  
The update interval for the program and the log file is by default one second  
but can be specified to be a longer period on the command line.

All data held by the modem and recognised by the API can be viewed by typing 'd' to dump the modem data.

The modem's operations log can be viewed by typing 'm'.

Usage
-----

In Windows use 5gtop.exe or 5gtop.bat(edit it to set up the parameters)
In Linux use 5gtop.bin
In a python envronment use 5gtop.py

usage (Windows): 
.\5gtop.exe [-h] [-a] -m MODEMIP -w PASSWORD [-p PINGIP] [-i INTERVAL] [-g GENERATION 4|5] [-u USER]

or (Linux)
./5gtop.bin [-h] [-a] -m MODEMIP -w PASSWORD [-p PINGIP] [-i INTERVAL] [-g GENERATION 4|5] [-u USER]

or Python
python 5gtop.py [-h] [-a] -m MODEMIP -w PASSWORD [-p PINGIP] [-i INTERVAL] [-g GENERATION 4|5] [-u USER]

options:

  * -h, --help          show the help screen, then exit
  * -a, --about         show the about screen, then exit
  
  * -m MODEMIP,    --modemip MODEMIP,
                        the IP address of the 5G modem(required)

  * -w PASSWORD,   --password PASSWORD,
                        admin password of the 5G modem(required)

  * -p PINGIP,     --pingip PINGIP,
                        IP address of host to be pinged(optional but recommended)

  * -i INTERVAL,   --interval INTERVAL,
                        measurement interval in seconds, default is one
                        second(optional)

  * -g GENERATION, --generation GENERATION,
                        4 for 4G or 5 for 5G(optional)

  * -u USER        --user ADMIN_USER,
                        Name of the modem admin user. Default is 'admin'


Commands
--------
  * q - quit 5gtop  
  * a - display this about file  
  * s - display the signal log  
  * m - display the modem log  
  * d - display a dump of all available modem data  
  * r - reboot the 5G modem. This takes about two minutes.


Log files display mode
----------------------
  * q - quit display mode    
  * End - go to end of log file.   
  * Home - return to the beginning of the log file  
  * PgUp or PgDn - page up or down through the log file  
  * Up or Down arrow - scroll up or down the log file.
  * The signal-log scrolls automatically as new values are added when placed at the end of the file.

Log files
---------
  * signal-log.txt - a record of all measurements at one second intervals. It is renewed every day at midnight and the old log file is renamed with the date. 30 days log files are kept.
  * modem-log.txt -the is the internal log kept by the modem.
  * modem-data.txt - a complete list of all internal data maintained by the modem.

Requirements
------------
icmplib is required for the ping function.
For icmplib to work without root access, in Linux, the following commands must first be entered

$ echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee -a /etc/sysctl.conf  
$ sudo sysctl -p

Python 3.8 or later is required if not using either of the binaries 5gtop.bin or 5gtop.exe.

Windows version 10 or later.

Ubuntu Linux version 20.04 or later.

When run for the first time it will print a list of missing libraries that need to be installed.  

PLMN Table
----------
A table of known South African 4G/5G service providers is kept in plmn.py.
It can be edited and extended(with care). Adhere strictly to the existing format.
This is a table of PLMN numbers and the corresponding name of the 4G/5G service provider.


Installation
------------  
1. Create a suitable folder and copy the zip file into it.
2. Unzip the file
3. Make file executable: chmod u+x 5gtop.py chmod u+x 5gtop.bin
4. Run python 5gtop.py -h to see command line options(or .\5gtop.exe -h or ./5gtop.bin).
5. It will check your version of python and print a list of needed libraries. 
6. Install them using pip.
7. Alternatively run the binary ./5gtop.bin or in Windows: .\5gtop.exe
8. These programs are complete in themselves and need nothing extra.
9. However in Linux you might need to install icmplib.
10. These binaries will work in Windows 10 or in Linux from Ubuntu 20.04 onwards.

Compilation
-----------
  * pip install nuitka
  * nuitka3 5gtop.py --standalone --onefile --nofollow-import-to=plmn [--low-memory]
  * or
  * nuitka  5gtop.py --standalone --onefile --nofollow-import-to=plmn [--low-memory]
  The low-memory option might be necessary in certain environments, for example a virtual machine.

Examples
--------
  * Python   -  python 5gtop.py -m 192.168.8.1 -w modem_admin_password -u admin -g 5 -p ping_ip    
  * Linux binary -  ./5gtop.bin -m 192.168.8.1 -w modem_admin_password -u admin -g 5 -p ping_ip  
  * Windows binary - .\5gtop.exe -m 192.168.8.1 -w modem_admin_password -u admin -g 5 -p ping_ip  
or, for Windows, edit 5gtop.bat to supply the command line parameters and double click to run it.


References:
-----------
https://github.com/Salamek/huawei-lte-api  
https://github.com/tigrawap/slit
https://www.digi.com/support/knowledge-base/understanding-lte-signal-strength-values  
https://5gstore.com/blog/2021/04/08/understanding-rssi-rsrp-and-rsrq/  
https://www.sharetechnote.com/html/Handbook_LTE_RSRP.html  
https://www.twilio.com/docs/iot/supersim/how-determine-good-cellular-signal-strength  
https://forum.huawei.com/enterprise/en/what-are-the-differences-between-rsrp-rsrq-rssi-and-sinr/thread/665359-869


Author
------
PDO Smith, 2.pdo.smith@gmail.com

Acknowledgements
----------------
This program uses the API produced by Salamek:  
https://github.com/Salamek/huawei-lte-api  

and the file pager 'slit' from tigrawap  
https://github.com/tigrawap/slit

This program(5gtop) is a derivative of
https://github.com/octave21/huawei-lte

License
-------
This work is licenced under  
GNU LESSER GENERAL PUBLIC LICENSE  
    Version 3, 29 June 2007

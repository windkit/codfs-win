Welcome
=====

This is the Windows Client for CodFS

Installation
=====

The Windows Client relies on Dokan library to provide a file system drive in user mode.
The Installation file of the library is included in the package
 - DokanInstall_0.6.0.exe

Preparation
=====

You have to configure the Client for IP and Ports of MDS and MONITOR.
Please replace the IP Address (192.168.0.1) with your CodFS Setup in 
 - common.xml

Running the Client
=====

You can use the included test.bat for easy start
 - Mount as R:
 - Shadown Folder at ./test
 - Created a Log file (codfs.log)
### NOTE
In order to use this on windows, add "/tmp/" to the beginning of all FIFO names

## Program Explaination
This program simulates a set of TOR packet switches with a master switch to control information
flow. Each packet switch is connected to the master through a TCP socket, and it's neighbours 
through FIFO's (one for reading and one). Port one and two of the switch is for it's neighbours,
while zero is for the master and three is for the blades. A user can provide a file for the 
program to read and it will process the lines based on which switch has been activated. A line
should have the switch being activated first, then the source IP, the destination IP, the IP
address of the server, and the port number for the server. A user may type info to be shown a 
table which changes based on whether the program has been invoked as the master, or a packet 
switch. They may type exit to end the program.

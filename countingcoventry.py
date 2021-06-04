#Counting Coventry 1.2.3
#Si Chun Lam
#27 May 2021

#Adapted from https://www.sans.org/blog/special-request-wireless-client-sniffing-with-scapy/
# This tells Python to import the scapy library for packet sniffing
from scapy.all import *
# Wi-Fi networks run on multiple channels, so we have code to hop between the Wi-Fi channels below to ensure we capture all devices.
import threading
import random
# To record the hostname of the device we import the socket (this is important if you have more than one device)
import socket
# To add a timestamp to each MAC address, we import the time from the operating system
import os, time

# This sets interface "wlan1", that is, the external USB wireless radio, into monitoring mode 
interface = "wlan1"

os.system("ifconfig " + interface + " down")
os.system("iwconfig " + interface + " mode monitor")
os.system("ifconfig " + interface + " up")

print ("Welcome to Counting Coventry.")
print ("Please make sure the date and time is correct. Change it with sudo date -s 'yyyy-mm-dd hh:mm:ss'")

print ("Beginning Counting Coventry on",socket.gethostname(),"at", datetime.now(),".")

# The following code essentially tells the Raspberry Pi to sniff for Wi-Fi MAC addresses, and record each MAC address detected along with the timestamp when the MAC address was detected and the device own hostname onto a csv text file called countingcoventry.csv in the same folder.  
#Code edited to use Dot11ProbeReq which MAY be better at capturing only packets requesting a Wi-Fi probe rather than all packets following GitHub thread at https://gist.github.com/dropmeaword/42636d180d52e52e2d8b6275e79484a0

with open("countingcoventry.csv", "a") as f:
                    f.write("Counting Coventry")
                    f.write(",")
                    f.write(str(datetime.now()))
                    f.write(",")
                    f.write(str(socket.gethostname()))
                    f.write ("\n")
                    f.write("mac")
                    f.write(",")
                    f.write("datetime")
                    f.write(",")
                    f.write("device")
                    f.write ("\n")


observedclients = []
def counting(coventry):
    if coventry.haslayer(Dot11ProbeReq):
#        if coventry.type == 0 and coventry.subtype == 8:
         stamgmtstypes = (0, 2, 4)
         print (coventry.addr2, datetime.now())
         with open("countingcoventry.csv", "a") as f:
                    f.write(str(coventry.addr2))
                    f.write(",")
                    f.write(str(datetime.now()))
                    f.write(",")
                    f.write(str(socket.gethostname()))
                    f.write ("\n")
         observedclients.append(coventry.addr2)
sniff(iface=interface, prn=counting)

# The following code is implemented as a parallel thread and is intended to tell the Raspberry Pi to hop between each of the Wi-Fi channels.  This is taken from code published by Shellvoide.
#Channel Hopping Thread https://www.shellvoide.com/python/how-to-code-a-simple-wireless-sniffer-in-python/
def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig

if __name__ == "__main__":
    thread = threading.Thread(target=hopper, args=('wlan1', ), name="hopper")
    thread.daemon = True
    thread.start()

    while True:
        pass

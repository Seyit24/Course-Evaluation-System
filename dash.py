import datetime
import logging
import urllib2
 
# Constants
timespan_threshhold = 3
 
# Globals
lastpress = datetime.datetime(1970,1,1)
 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
 
 
def button_pressed_dash1():
  global lastpress
  thistime = datetime.datetime.now()
  timespan = thistime - lastpress
  if timespan.total_seconds() > timespan_threshhold:
    current_time = datetime.datetime.strftime(thistime, '%Y-%m-%d %H:%M:%S')
    print 'Dash button pressed at ' + current_time
    urllib2.urlopen('http://pi:8083/fhem?cmd.LED=set%20LED%20toggle&room=Haussteuerung')
 
  lastpress = thistime
 
 
def udp_filter(pkt):
  options = pkt[DHCP].options
  for option in options:
    if isinstance(option, tuple):
      if 'requested_addr' in option:
        # we've found the IP address, which means its the second and final UDP request, so we can trigger our action
        mac_to_action[pkt.src]()
        break
 
 
mac_to_action = {'34:d2:70:cf:b8:84' : button_pressed_dash1}
mac_id_list = list(mac_to_action.keys())
 
print "Waiting for a button press..."
sniff(prn=udp_filter, store=0, filter="udp", lfilter=lambda d: d.src in mac_id_list)
 
if __name__ == "__main__":
  main()

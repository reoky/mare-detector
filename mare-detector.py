#!/usr/bin/env python
import sys
import threading
import time
from scapy.all import *

# Mare Detector
def main():
  # Queue to store the last n packets from the wire/air (last ~100 packets)
  packets = []
  print("-" * 46)
  print("Mare Detector: Watching for suspicious traffic.." )
  print("-" * 46)

  # Check for args and set interface
  if (len(sys.argv) != 2):
    printMsg("No interface specified. Exiting.")
    sys.exit()
  interface = sys.argv[1]
  printMsg("Selected interface: %s" % interface)

  # Start the monitor thread to constantly search the queue for IDS items
  monitorThread = threading.Thread(target=quantum_test_thread, args=("monitor-thread", packets)).start()

  # Start sniffing with callback dumping packets into a queue
  sniff(iface=interface, prn=lambda packet: packets.append(packet), filter="tcp", store=0)

# Test to see whether a packet with dup SEQ numbers has been recieved recently
def quantum_test_thread(name, packets):
  logfile = "%s-mare-detect-log.pcap" % time.time()

  while (True):
    print(len(packets))

    # Test packets for duplicate seq with varied payloads
    for testPacket in packets:
      for packet in packets:
        if (testPacket[TCP].seq == packet[TCP].seq): # seq match
          #if (testPacket[IP].ttl != packet[IP].ttl): ## ttl mismatch
          printMsg("Printing two packets with same ttl and seq number:")
          wrpcap(logfile, (testPacket, packet))

    # Pop/trim old packets from queue
    if (len(packets) > 100):
      while (len(packets) > 100):
        packets.pop()
    time.sleep(5)

# Print out individual debug messages
def printMsg(msg):
  print("[mare] - " + msg)

main()
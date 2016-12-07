#!/usr/bin/env python
import os
import sys
import threading
import time
from scapy.all import *

# Mare Detector
def main():
  mtx = threading.Lock()
  packets = [{}, {}] # Dict of 5 seconds of packets, List for shallow-copy in monitor_thread

  print("-" * 48)
  print("Mare Detector: Watching for suspicious traffic.." )
  print("-" * 48)

  # Check for args and set interface
  if (len(sys.argv) != 2):
    printMsg("No interface specified. Exiting.")
    sys.exit()
  interface = sys.argv[1]
  printMsg("Selected interface: %s" % interface)

  # Make logging directory
  os.mkdir("logs")

  # Start the monitor thread to constantly search the queue for IDS items
  monitorThread = threading.Thread(target=monitor_thread, args=("monitor-thread", mtx, packets)).start()

  def prn(packet):
    key = "%s" % packet["TCP"].seq
    mtx.acquire()
    packets[0].setdefault(key, []).append(packet)
    mtx.release()

  # Start sniffing with callback dumping packets into a dict (md5(TCP.seq) => packet)
  sniff(iface=interface, prn=prn, filter="tcp src port 80", store=0)

# Test to see whether a packet with dup SEQ numbers has been recieved recently
def monitor_thread(name, mtx, packets):

  while (True):
    time.sleep(5)
    printMsg("Rate: %s pkt/s, (Current 5s: %s, Last 5s: %s)" % ((len(packets[0]) + len(packets[1])/10), len(packets[0]), len(packets[1])))

    # Last 5 seconds
    mergedPackets = packets[1]

    # Lock to get current 5 second snippet of packets
    with mtx:
      packets[1] = packets[0]
      packets[0] = {}

    # Make a copy and merge the snippets together
    mergedPackets.update(packets[1])

    # Packets from the current iteration with duplicate SEQ numbers
    duplicateSEQ = []
    for key in mergedPackets:

      # Find duplicate SEQ numbers
      if (len(mergedPackets[key]) > 1):
        for packet in mergedPackets[key]:
          if packet[IP].len > 52: # min size
            duplicateSEQ.append(packet)

        # Check if payload size or TTL suddenly change
        sizeAndTTL = ()
        first = True
        quantum = False
        for packet in duplicateSEQ:
          if first:
            first = False
            sizeAndTTL = (packet[IP].len, packet[IP].ttl)
          else:
            if (sizeAndTTL != (packet[IP].len, packet[IP].ttl)):
              quantum = True
              print("Size: %s, TTL: %s" % (sizeAndTTL[0], sizeAndTTL[1]))

        # If yes, write the packets to PCAP
        if quantum:
          quantum = False
          printMsg("Possible quantum insert deteced. Written to PCAP.")
          wrpcap("logs/%s-mare-detector.pcap" % time.time(), duplicateSEQ)

# Print out individual debug messages
def printMsg(msg):
  print("[mare] - " + msg)

main()
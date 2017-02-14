# Colum Foskin - 20062042 - Cloud Infrastructure - Assignment 1
"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's quite similar to the one for NOX.  Credit where credit due. :)
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

import datetime
import os 
import csv
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.util import dpid_to_str

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    log.debug("MAC table setup")

    self.file = open('pox/misc/firewall.csv', 'rb')
    self.reader = csv.reader(self.file, delimiter=',')
    # this is an array of the edge switches macs so I can only install rules on those
    self.edgeSwitches = ['00-00-00-00-00-04','00-00-00-00-00-05','00-00-00-00-00-06', '00-00-00-00-00-07']
    self.firewall = self.readFirewall()

# Read in the firewall rules from a csv file
  def readFirewall (self):
    self.iterRows = iter(self.reader)
    next(self.iterRows)
    firewall = []
    for row in self.iterRows:
        firewall.append(row[0:])
        print row
    return firewall 

# Handle incoming packets
  def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        self.mac_to_port[(event.connection, packet.src)] = event.port

        dst_port = self.mac_to_port.get((event.connection, packet.dst))

        if dst_port is None:
            # Don't know where the destination is yet so send the packet out all ports (except the one it came in on!)
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
        else:
            # Since we know the switch ports for both the source and dest
            # MACs, we can install rules for both directions.
            msg = of.ofp_flow_mod()
            msg.match.dl_dst = packet.src
            msg.match.dl_src = packet.dst
            msg.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(msg)

            # This is the packet that just came in -- we want to
            # install the rule and also resend the packet.
            msg = of.ofp_flow_mod()
            msg.data = event.ofp  # Forward the incoming packet
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.actions.append(of.ofp_action_output(port=dst_port))
            event.connection.send(msg)

            log.debug("Installing %s.%i -> %s.%i AND %s.%i -> %s.%i" %
              (packet.dst, dst_port, packet.src, event.ofp.in_port,
              packet.src, event.ofp.in_port, packet.dst, dst_port))

# Checking if the switch booting up is an edge switch - to avoid installing flows on all switches unnecessarily 
  def checkSwitchType (self, switchId):
      log.info("Checking if switch %s  is an edge switch...", switchId) 
      if switchId in self.edgeSwitches:
          log.info("Switch IS an edge switch - Installing firewall rules...") 
          return True
      else:
        log.info("Switch is NOT an edge switch - NOT installing firewall rules") 
        return False 
    
# On switch boot up -  install firewall rules
  def _handle_ConnectionUp (self, event):   
        connection = event.connection
        dpid = connection.dpid
        log.info("Switch %s has come up.",dpid_to_str(dpid))
        # check if the present switch is an edge switch
        result = self.checkSwitchType(dpid_to_str(dpid))
        if result:
            for rule in self.firewall:
                if rule[0] == 'mac':
                    macSrc = rule[1] #get mac src
                    macDst = rule[2] # get mac dest
                    msg = of.ofp_flow_mod()
                    msg.match.dl_src = EthAddr(macSrc)
                    msg.match.dl_dst = EthAddr(macDst)
                    log.debug("Installing %s  Eth rule <-> %s" % (macSrc, macDst))
                    event.connection.send(msg)
                    msg = of.ofp_flow_mod()
                    msg.match.dl_src = EthAddr(macDst)
                    msg.match.dl_dst = EthAddr(macSrc)
                    event.connection.send(msg)
                    log.debug("Installing %s Eth rule <-> %s" % (macDst, macSrc))

                if rule[0] == 'ip':
                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = 0x800
                    ipSrc = rule[1] # get ip src
                    ipDst = rule[2] #get ip dest
                    if (msg.match.nw_src == IPAddr(ipSrc)):
                        print 'true'
                    msg.match.nw_dst = IPAddr(ipDst)
                    
                    # block destination port 80 - could also be * for ip rule 
                    # so needed if statement to not break things!
                    if(rule[3] == '80'):
                        log.info('setting dest port')
                        msg.tp_dst = int(rule[3])
                    event.connection.send(msg)
                    log.debug("Installing IP rule %s  <-> %s" % (ipSrc, ipDst))

                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = 0x800
                    msg.match.nw_src = IPAddr(ipDst)
                    msg.match.nw_dst = IPAddr(ipSrc)
                    # block destination port 80 - could also be * for ip rule 
                    # so needed if statement to not break things!
                    if(rule[3] == '80'):
                        log.info('setting dest port')
                        msg.tp_dst = int(rule[3])
                    event.connection.send(msg)
                    log.debug("Installing IP rule%s <-> %s" % (ipDst, ipSrc))
        log.debug("firewall updated")

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)



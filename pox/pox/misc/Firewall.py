
# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

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

    self.file = open('pox/misc/firewallMini.csv', 'rb')
    self.reader = csv.reader(self.file, delimiter=',')
    self.edgeSwitches = ['00-00-00-00-00-04','00-00-00-00-00-05','00-00-00-00-00-06', '00-00-00-00-00-07']
    self.firewall = self.readFirewall()

# Read in the firewall rules from a csv file
  def readFirewall (self):
    self.iterRows = iter(self.reader)
    next(self.iterRows)
    firewall = []
    for row in self.iterRows:
        firewall.append(row[0:])
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
            # We don't know where the destination is yet.  So, we'll just
            # send the packet out all ports (except the one it came in on!)
            # and hope the destination is out there somewhere. :)
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
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
        result = self.checkSwitchType(dpid_to_str(dpid))
        if result:
            for rule in self.firewall:
                if rule[0] == 'ip':
                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = 0x800
                    ipSrc = rule[1]
                    ipDst = rule[2]
                    msg.match.nw_src = IPAddr(ipSrc)
                    msg.match.nw_dst = IPAddr(ipDst)
                    msg.in_port = rule[3]
                    event.connection.send(msg)
                    log.debug("Installing %s <-> %s , port: %s" % (ipSrc, ipDst, rule[3]))
                elif rule[0] == 'mac':
                    macSrc = rule[1]
                    macDst = rule[2]
                    msg = of.ofp_flow_mod()
                    msg.match.dl_src = EthAddr(macSrc)
                    msg.match.dl_dst = EthAddr(macDst)
                    log.debug("Installing %s <-> %s" % (macSrc, macDst))
                    event.connection.send(msg)
                    msg = of.ofp_flow_mod()
                    msg.match.dl_src = EthAddr(macDst)
                    msg.match.dl_dst = EthAddr(macSrc)
                    event.connection.send(msg)
                    log.debug("Installing %s <-> %s" % (macDst, macSrc))
        log.debug("firewall updated")

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)



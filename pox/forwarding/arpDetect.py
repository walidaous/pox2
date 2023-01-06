# Copyright 2011-2012 James McCauley
# Copyright 2014-2015 Vamshi Reddy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An L2 learning switch which can detect ARP spoofing attacks in the networks.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import pox.lib.packet as pkt
import time
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

# Hosts hash table key: HostIP Value: MAC
hosts = {}

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

# DHCP message handler
def _handle_dhcp_lease(event):
  print ("DHCP Packet \n")
  print ("DHCP packet IP "+str(event.ip)+", MAC: "+str(event.host_mac))
  # Add this IP and MAC to the hosts dictionary
  if event.ip != None and event.host_mac != None :
  	hosts[str(event.ip)] = str(event.host_mac)



class LearningSwitch (object):
  """
  The learning switch "brain" associated with a single OpenFlow switch.
  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.
  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.
  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).
  In short, our algorithm looks like this:
  For each packet from the switch:
  1) Use source address and switch port to update address/port table
  2) Is transparent = False and either Ethertype is LLDP or the packet's
     destination address is a Bridge Filtered address?
     Yes:
        2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send the packet out appropriate port
  """
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

    ######## Now add entries for ARP traffic.######################
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type = pkt.ethernet.ARP_TYPE);
    msg.idle_timeout = of.OFP_FLOW_PERMANENT;
    msg.hard_timeout = of.OFP_FLOW_PERMANENT;
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(msg)
	
	######### Add entries to intercept the DHCP traffic.###########
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(nw_proto = 17, tp_src = 67 , tp_dst = 68 );
    msg.idle_timeout = of.OFP_FLOW_PERMANENT;
    msg.hard_timeout = of.OFP_FLOW_PERMANENT;
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    print ("Installed flow entries\n")

	########## Register a handler for DHCP lease packets #########
    core.DHCPD.addListenerByName('DHCPLease',_handle_dhcp_lease)

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    def handle_spoof(mac=None):
        print ("**************Spoofing Detected from host with MAC "+str(mac)+" ******************\n")
        actions = []
        actions.append(of.ofp_action_output(port = of.OFPP_NONE)) # Drop
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=60, # Drop packets for 60 seconds
                                hard_timeout=60, # Drop packets for 60 seconds
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=of.ofp_match.from_packet(packet,
                                                               event.port))
        event.connection.send(msg.pack())
        print ("Installed an entry to drop all the packets from the port")

	# If ARP packet, then check if the packet is spoofed. If its not, then continue with the flow.
    if packet.type == packet.ARP_TYPE:
		
		print ("Its ARP\n")

		if packet.payload.opcode == pkt.arp.REQUEST :
			src_mac_eth = packet.src
			dst_mac_eth = packet.dst
			src_ip_arp = packet.payload.protosrc
			src_mac_arp = packet.payload.hwsrc 
			dst_ip_arp = packet.payload.protodst

			print ("Source MAC : "+str(src_mac_arp)+"\n";)
			print ("Dest MAC : "+str(dst_mac_eth)+"\n";)
			print ("Source IP : "+str(src_ip_arp)+"\n";)
			print ("Source DST : "+str(dst_ip_arp)+"\n";)
			
			# Check whether this IP exists in the hash table
			
			if src_mac_eth != src_mac_arp :
				# Spoofing detected
				#drop()
				handle_spoof(src_mac_eth)
				return
			else:
				# MAC addresses matched
				# Check if the source ip and src MAC are matched and stored earlier
				print ("Table MAC : "+hosts[str(src_ip_arp)]+" and mac "+str(src_mac_arp)+"\n";)
				if EthAddr(hosts[str(src_ip_arp)]) != src_mac_arp:
					print ("Spoofing detected: IP and MAC not matched\n")
					#drop()
				        handle_spoof(src_mac_eth)
					print ("Dropping\n")
					return
				else:
					# Valid Arp Packet
					print ("Valid ARP\n");
					# Check if the dest host is already there in the network
					if dst_ip_arp not in hosts.keys():
						# Spoofing detected
						print ("Spoofing detected: Dest host ip not in table\n")
						#drop()
				                handle_spoof(src_mac_eth)
						return
					else:
						if str(dst_mac_eth) == "ff:ff:ff:ff:ff:ff":
							# Now flood the packets to all the other ports
							print ("Flooding the packets\n")
						else:
							# ARP Request should be broadcast. Some are unicast sometimes.
							print ("Unicast ARP packet detected\n")
	# If DHCP, then intercept DHCP Ack packets
    #elif packet.type == pkt.ethernet.IP_TYPE:	
	#	if packet.payload.protocol == pkt.ipv4.UDP_PROTOCOL:
	#		if packet.payload.payload.srcport == pkt.dhcp.SERVER_PORT:
	#			if packet.payload.payload.dstport == pkt.dhcp.CLIENT_PORT:
	#				print "DHCP Packet\n"



    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)


class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))

# Copyright 2012 James McCauley
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
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import csv
import datetime
from pox.lib.recoco import Timer
log = core.getLogger()
TimerQuantumDuration = 10


class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
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
    self.ip_to_mac = {}
    self.ip_to_mac_time_track = {}
    #Timer(TimerQuantumDuration, self.Clean_Tables, recurring = True)

  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)
  def send_packet (self, buffer_id, raw_data, out_port, in_port):
    msg =of.ofp_packet_out()
    msg.in_port = in_port
    if buffer_id != -1 and buffer_id is not None:
      msg.buffer_id = buffer_id
    else:
      if raw_data is None:
        return
      msg.data = raw_data
    action = of.ofp_action_output(port=out_port)
    msg.actions.append(action)
    self.connection.send(msg)
  def arp_spoof_detected(self, packet, packet_in):
    ipsrc=self.int_of_ip(packet, packet_in)
    arp = packet.find('arp')
    if arp is not None:
      macsrc=str(arp.hwsrc)
    ip = packet.find('ipv4')
    if ip is not None:
      macsrc=str(packet.src)
    if ipsrc in self.ip_to_mac:
      if self.ip_to_mac[ipsrc] != macsrc:
        return True
    self.ip_to_mac[ipsrc] = macsrc
    return False
  def check_arp_spoof(self, packet, packet_in):
    if self.arp_spoof_detected(packet, packet_in):
      arp = packet.find('arp')
      if arp is not None:
        tempipstring=str(self.ip_to_mac[arp.protosrc.toUnsignedN()])
        print("\n ===================================================== \n")
        print("Dup IP to MAC!!!"+ str(arp.protosrc)+"alreadytaken by "+ tempipstring + ". " +  str(arp.hwsrc) + " may be spoofing!")
        print("\n ===================================================== \n")
  def int_of_ip (self, packet, packet_in):
    arp = packet.find('arp')
    if arp is not None:
      ipsrc=arp.protosrc.toUnsignedN()
    ip = packet.find('ipv4')
    if ip is not None:
      ipsrc=ip.srcip.toUnsignedN()
    return ipsrc
  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    mac_src = packet.src
    mac_dst = packet.dst
    print(mac_src, " ----> ", mac_dst)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    self.mac_to_port[str(packet.src)] = packet_in.in_port
    mac_src = packet.src
    my_in_port = packet_in.in_port
    # Check if th src mac exits in dict
    self.check_arp_spoof(packet, packet_in)
    if self.arp_spoof_detected(packet, packet_in):
      log.debug("Installingdrop flow...")
      msg = of.ofp_flow_mod()
      msg.match=of.ofp_match(dl_src=packet.src)
			#msg.idle_timeout = TimerQuantumDuration * 2 
      msg.actions.append(of.ofp_action_output(port=100))
      self.connection.send(msg)
    else:
      if mac_src not in self.mac_to_port:
        #print("New mac src ---> ", mac_src)
        self.mac_to_port[mac_src] = my_in_port
        mac_dst = packet.dst
      
      if mac_dst in self.mac_to_port:
        print("Mac dst already known --> ", mac_dst)
        my_out_port = self.mac_to_port[mac_dst]
        print("Resend packet in port ***> ", my_out_port)
        self.resend_packet(packet_in, my_out_port)
      else:
      	#print("Mac dst unknown  --> ", mac_dst) 
        self.resend_packet(packet_in, of.OFPP_ALL)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    time_stmp = datetime.datetime.now()
    packet = event.parsed # This is the parsed packet data.
    mac_src = packet.src
    mac_dst = packet.dst
    with open('stats.csv', 'a+') as mycsv:
        mycsv.write(str(time_stmp)+','+str(mac_src)+','+str(mac_dst)+'\n')
    mycsv.close()
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    # self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)
  def Clean_Tables(self):
    print("Show Table")
    print(self.ip_to_mac)


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)

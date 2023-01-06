from pox.core import core



# A set of ports to block

block_ports = set()



def block_handler (event):

  # Handles packet events and kills the ones with a blocked port number



  tcpp = event.parsed.find('tcp')

  if not tcpp: return # Not TCP

  if tcpp.srcport in block_ports or tcpp.dstport in block_ports:

    # Halt the event, stopping l2_learning from seeing it

    # (and installing a table entry for it)

    core.getLogger("blocker").debug("Blocked TCP %s <-> %s",

                                    tcpp.srcport, tcpp.dstport)

    event.halt = True



def unblock (*ports):

  block_ports.difference_update(ports)



def block (*ports):

  block_ports.update(ports)



def launch (ports = ''):



  # Add ports from commandline to list of ports to block

  block_ports.update(int(x) for x in ports.replace(",", " ").split())



  # Add functions to Interactive so when you run POX with py, you

  # can easily add/remove ports to block.

  core.Interactive.variables['block'] = block

  core.Interactive.variables['unblock'] = unblock



  # Listen to packet events

  core.openflow.addListenerByName("PacketIn", block_handler)

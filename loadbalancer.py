#check out the pox wiki for any confusion
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.recoco import Timer
from pox.openflow.discovery import Discovery
from array import *
import sys

#log = logging.getLogger() #get the default system logger
#log.setLevel(logging.NOTSET) #pushes the log messages to stdout
connections=core.openflow._connections.values()
switches = []
found = {}
tconnections = []
hconnections = []
hdpids = []
udptoggle = [1 for j in range(8)]
distances = [[1000 for j in range(8)] for i in range(8)]
ports = [[0 for j in range(8)] for i in range(8)]
previous = [[0 for j in range(8)] for i in range(8)]
shortestpath = 0
proxy_bool = 0
proxy_switch = 0
proxy_dst = 0
found_proxy = 0
port_of_proxyhost = 0
timeout_sw = {}

class myswitch (object):
	def __init__ (self, connection):
		self.connection = connection
		self.macToPort = {} #the array to keep the mac to port mapping
		connection.addListeners(self) #add the listeners
	def _handle_PacketIn (self, event): #handle packet in
		packet = event.parsed #parse the packet
		if proxy_bool and packet.payload.srcip == proxy_dst and not found_proxy:
			proxy_switch = event.dpid
			found_proxy = 1
			port_of_proxyhost = event.port
			packet.payload.srcip = "1.1.1.1"
			event.ofp.data = packet
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
			msg.data = event.ofp
			msg.in_port = event.port
			self.connection.send(msg)
			return
		if proxy_bool and packet.payload.dstip == "1.1.1.1" and event.dpid == proxy_switch:
			packet.payload.dstip == proxy_dst
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = port_of_proxyhost))
			msg.data = event.ofp
			msg.in_port = event.port
			self.connection.send(msg)
			return
		if packet.src not in found:
			found[packet.src] = event.dpid
		if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
			if event.ofp.buffer_id is not None:
				msg = of.ofp_packet_out()
				msg.buffer_id = event.ofp.buffer_id
				event.ofp.buffer_id = None
				msg.in_port = event.port
				self.connection.send(msg)
				return
		if not shortestpath:
			if packet.dst not in self.macToPort or packet.dst.is_multicast: #if not found then flood the packet
				self.macToPort[packet.src] = event.port
				msg = of.ofp_packet_out()
				msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
				msg.data = event.ofp
				msg.in_port = event.port
				self.connection.send(msg)
				return
			else:
				port = self.macToPort[packet.dst] #if found then create a table entry for the switch and then add the entry to table
				if event.dpid not in hdpids:
					msg = of.ofp_flow_mod() #new table modification
					msg.match = of.ofp_match.from_packet(packet, event.port) #new matching criteria
					msg.idle_timeout = 30 #timeout
					msg.hard_timeout = 30 #other timeout
					msg.actions.append(of.ofp_action_output(port = port))
				else:
					msg = of.ofp_flow_mod() #new table modification
					msg.match = of.ofp_match.from_packet(packet, event.port) #new matching criteria
					if udptoggle[event.dpid]:
						msg.match.nw_proto = 17
						msg.actions.append(of.ofp_action_output(port = none))
					else:
						msg.actions.append(of.ofp_action_output(port = port))
					msg.idle_timeout = timeout_sw[event.dpid] #timeout
					msg.hard_timeout = timeout_sw[event.dpid] #other timeout
				msg.data = event.ofp
				self.connection.send(msg)
				return
		else:
			if packet.dst in found:
				switchadj = found[packet.dst]
				prev = previous[event.dpid][switchadj]
				while prev != 0:
					prev = previous[event.dpid][switchadj]
				port = ports[event.dpid][prev]
				if event.dpid not in hdpids:
					msg = of.ofp_flow_mod() #new table modification
					msg.match = of.ofp_match.from_packet(packet, event.port) #new matching criteria
					msg.idle_timeout = 30 #timeout
					msg.hard_timeout = 30 #other timeout
					msg.actions.append(of.ofp_action_output(port = port))
				else:
					msg = of.ofp_flow_mod() #new table modification
					msg.match = of.ofp_match.from_packet(packet, event.port) #new matching criteria
					if udptoggle[event.dpid]:
						msg.match.nw_proto = 17
						msg.actions.append(of.ofp_action_output(port = none))
						udptoggle[event.dpid] = 0
					else:
						msg.actions.append(of.ofp_action_output(port = port))
						udptoggle[event.dpid] = 1
					msg.idle_timeout = timeout_sw[event.dpid] #timeout
					msg.hard_timeout = timeout_sw[event.dpid] #other timeout
				msg.data = event.ofp
				self.connection.send(msg)
			else:
				msg = of.ofp_packet_out()
				msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
				msg.data = event.ofp
				msg.in_port = event.port
				self.connection.send(msg)

def handle_timer_func (): #after the time interval currenttime call this function
	for cn in tconnections: #all the connections i.e. switches
		cn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request())) #send a flow stat request to the switches

def _handle_flowstats_received (event): #when flow stat are received from a switch
	tcppackets = 0
	udppackets = 0
	totalpackets = 0
	for f in event.stats: #the follow stats are received like a array of packet headers, so from that array traverse through it
		if f.match.nw_proto is not None:
			print "the match protp :", f.match.nw_proto
			if f.match.nw_proto == 6:
				tcppackets=tcppackets+1
			elif f.match.nw_proto == 17:
				udppackets=udppackets+1
			totalpackets = totalpackets+1
	print "ratio of upd/total : ", udppackets/totalpackets, udppackets, totalpackets
	if udppackets/totalpackets > 80 and event.dpid not in hdpids:
		timeout_sw[event.dpid] = 4
		hdpids.append(event.dpid)
	elif udppackets/totalpackets > 60 and event.dpid not in hdpids:
		timeout_sw[event.dpid] = 2
		hdpids.append(event.dpid)
	elif event.dpid in hdpids:
		hdpids.remove(event.dpid)


class mycontroller (object):
	def __init__ (self):
		core.openflow.addListeners(self)
		core.listen_to_dependencies(self)
		core.openflow.addListenerByName("FlowStatsReceived", _handle_flowstats_received) #flowstatreceived listener
	def _handle_ConnectionUp(self, event):
		switches.append(event.dpid)
		tconnections.append(event.connection)
		distances[0][event.dpid] = event.dpid
		distances[event.dpid][0] = event.dpid
		distances[event.dpid][event.dpid] = 0
		myswitch(event.connection)
	def _handle_openflow_discovery_LinkEvent(self, event):
		l = event.link
		distances[l.dpid1][l.dpid2]=1
		ports[l.dpid1][l.dpid2]=l.port1

def floydWarshall():
	msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
	for connection in tconnections:
  		connection.send(msg)
  	for k in switches:
  		for i in switches:
  			for j in switches:
  				if distances[i][k] + distances[k][j] < distances[i][j]:
  					distances[i][j] = distances[i][k]+distances[k][j]
  					previous[i][j] = k
  	shortestpath=1

def launch ():
	dec = raw_input("Enable Proxy Server Y/N?")
	if dec == "Y":
		print "Proxy Server Enabled."
		proxy_bool = 1
		proxy_dst = raw_input("Enter destination IP address.")
	elif dec == "N":
		print "Proxy Server Disabled."
	else:
		print "Enter correct option."

	core.registerNew(mycontroller)
	Timer(10, handle_timer_func, recurring = True) #after the time interval currenttime call this function
	Timer(20, floydWarshall, recurring = False)

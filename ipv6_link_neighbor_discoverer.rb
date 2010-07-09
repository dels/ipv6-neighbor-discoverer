#
# ipv6 neighbor discovery within the link 
# extended some examples of jon hart
#
# dominik.elsbroek@gmail.com
#

require 'rubygems'
require 'racket'
require 'pcaprub'

include Racket

ICMP_IDENTIFIER = 4711

dev = ARGV[0] || "vpn6"
eth_src_addr = ARGV[1] || L2::Misc.randommac;
ipv6_src_addr = ARGV[2] || L3::Misc.ipv62long(L3::Misc::linklocaladdr(eth_src_addr))
timeout = ARGV[3] || 65535

# open capturing device
cap = Pcap.open_live(dev, timeout, true, 5)
raise RuntimeError, "unable to open device #{dev}" unless cap

# create racket stuff ...
rpacket = Racket::Racket.new
rpacket.iface = dev

# ethernet stuff...
rpacket.l2 = L2::Ethernet.new
rpacket.l2.src_mac = eth_src_addr
rpacket.l2.dst_mac = "33:33:00:00:00:01"
rpacket.l2.ethertype = 0x86DD # ipv6

# ip stuff...
rpacket.l3 = L3::IPv6.new
rpacket.l3.src_ip = 
rpacket.l3.dst_ip = L3::Misc.ipv62long("ff02::1")
# next header is icmpv6
rpacket.l3.nhead = 58

# icmp stuff
rpacket.l4 = L4::ICMPv6EchoRequest.new
rpacket.l4.id = ICMP_IDENTIFIER
rpacket.l4.sequence = 1
rpacket.l4.fix!(rpacket.l3.src_ip, rpacket.l3.dst_ip)

# send the packet
f = rpacket.sendpacket

puts "sent echo request (size: #{f})"

# and capture all packets which are icmpv6 and have the type 129
cap.each do  |pkt|
  eth = L2::Ethernet.new(pkt)
  # we want ipv6 traffic only
  next unless eth.ethertype == 0x86DD 

  ip = L3::IPv6.new(eth.payload)
  # we want icmpv6 only
  next unless 58 == ip.nhead 

  if L4::ICMPv6.new(ip.payload).type == L4::ICMPv6::ICMPv6_TYPE_ECHO_REPLY
    icmpv6_echo_reply = L4::ICMPv6Echo.new ip.payload
  else
    next
  end
  # we only want packets with the correct id we just have sent
  unless ICMP_IDENTIFIER == icmpv6_echo_reply.id
    puts "incorrect id: #{icmpv6_echo_reply.id}"
    next
  end
  # print all link local ip addresses have responded
  puts "#{Racket::L3::Misc::long2ipv6 ip.src_ip} is alive and responding"
end

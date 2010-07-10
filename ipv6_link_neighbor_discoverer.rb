# Copyright 2010 Dominik Elsbroek. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
# 
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY Dominik Elsbroek ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Dominik Elsbroek OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The views and conclusions contained in the software and documentation are those of the
# authors and should not be interpreted as representing official policies, either expressed
# or implied, of <copyright holder>.

#
# ipv6 neighbor discovery within the current link 
# 
# proof of concept
#
# dominik.elsbroek@gmail.com 2010-07-08
#

require 'rubygems'
require 'racket'
require 'pcaprub'

include Racket

ICMP_IDENTIFIER = (rand * 100000).to_i

dev = ARGV[0] || "eth0"
eth_src_addr = ARGV[1] || L2::Misc.randommac;
ipv6_src_addr = L3::Misc.ipv62long(ARGV[2]) || L3::Misc.ipv62long(L3::Misc::linklocaladdr(eth_src_addr))
snaplen = ARGV[3] || 65535

# open capturing device
# see http://www.goto.info.waseda.ac.jp/~fukusima/ruby/pcap/doc/Capture.html
cap = Pcap.open_live(dev, snaplen, true, 5)
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
rpacket.l3.src_ip = ipv6_src_addr
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
  
  next unless L4::ICMPv6.new(ip.payload).type == L4::ICMPv6::ICMPv6_TYPE_ECHO_REPLY
  icmpv6_echo_reply = L4::ICMPv6Echo.new ip.payload

  # we only want packets with the correct id we just have sent
  next unless ICMP_IDENTIFIER == icmpv6_echo_reply.id

  # print all link local ip addresses which have responded
  puts "#{Racket::L3::Misc::long2ipv6 ip.src_ip} is alive and responding"
end



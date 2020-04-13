#
# Copyright (c) 2020 Raul Caro.
#
# This file is part of ICMPack 
# (see https://github.com/rcaroncd/ICMPack).
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
from icmp import Packet, Offsets, Sizes
from sys import argv
import socket


# It is necessary to pass the ip address or hostname of the server
dest_addr = argv[1]
data = bytes(argv[2],'utf-8') if len(argv) == 3 else None

try:
	my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
except socket.error as e:
	print("Exception socket(): ", e)
	exit(1)

try:
	host = socket.gethostbyname(dest_addr)
except socket.gaierror as e:
	print("Exception gethostbyname(): ", e)
	exit(1)

# Generating the ICMP Echo Request package
request_packet = None

if data:
    request_packet = Packet(ping=False)
    request_packet.pack_request(data)
else:
    request_packet = Packet(ping=True)
    request_packet.pack_request()

icmp_raw_packet = request_packet.toBytes()

print("Request Packet:")
print(request_packet)
print("[*] DATA Sent: ", request_packet.data)

my_socket.sendto(icmp_raw_packet, (dest_addr, 1))

# Transforming the received response bytes into ICMP packet format
rec_packet, addr = my_socket.recvfrom(65535)

response_packet = None

if data:
    response_packet = Packet(ping=False)
else:
    response_packet = Packet(ping=True)

response_packet.unpack(rec_packet)
print("Response Packet:")
print(response_packet)
print("[*] DATA Recv: ", response_packet.data)

#!/usr/bin/python3

from typing import Dict, Union, Tuple, Optional
import base64
import json
import os
import socket
import struct
import sys
import time

__author__ = "ntoskrnl4"
__version__ = "0.4"

# Sample ping packet data sent by the vanilla 1.15.2 client
# Captured by reading a raw Python socket

# 10 - Following packet's length
# 00 - This packet's ID
# c2 - VarInt: Client version (c204 = 578)
# 04 - VarInt: Client version
# 09 - Following string's length
# 31 - '1'
# 32 - '2'
# 37 - '7'
# 2e - '.'
# 30 - '0'
# 2e - '.'
# 30 - '0'
# 2e - '.'
# 31 - '1'
# 63 - Target port: high byte (63dd = 25565)
# dd - Target port: low byte
# 01 - Next state (01: Status)

# 01 - Following packet's length
# 00 - This packet's ID (00 w/o fields: Request)


# VarInts are a convoluted way of saving barely a few bytes of data on the
# network stream, by encoding a number alongside a bit ndicating if there's more
# bytes after it to that number. https://wiki.vg/Protocol#VarInt_and_VarLong
def decode_varint(sock) -> Union[int, Tuple[int, bytes]]:
	"""
	Read a VarInt from a socket or (string or string-like). Returns the number,
	alongside the rest of the data if string-like.
	
	:param sock: Socket to read a VarInt from.
	:raises ValueError: The VarInt we read exceeded int32 limits.
	:raises TypeError: We got back b''/EOF from a socket.
	:raises IndexError: We tried to read b'' from a string.
	:return: The number that was read.
	"""
	n_bytes = 0
	number = 0
	byte = 128  # The byte we are reading in from the socket
	while (byte & 0x80) != 0:
		if isinstance(sock, bytes):
			byte = sock[0]
			sock = sock[1:]
		else:
			byte = ord(sock.recv(1))
		value = byte & 0x7f
		number |= value << (7*n_bytes)  # In-place OR operation
		n_bytes += 1
		if n_bytes > 4:
			raise OverflowError("VarInt too large")
	if isinstance(sock, bytes):
		return number, sock
	else:
		return number


def encode_varint(number):
	"""
	Write a VarInt to a string.
	
	:param number: Number to encode as a VarInt.
	:return: The encoded VarInt.
	"""
	# Python ints are variable length, which means there's no fixed size.
	# Typical programming language implementation exploits the sign bit moving
	# when doing bitwise shifts, but that's not possible here.
	# To force an int32-like type, we use the `struct` module to make it fit.
	number = struct.unpack(">I", struct.pack(">i", number))[0]
	out = b""
	while True:
		part = number & 0x7f
		number = number >> 7
		if number != 0:
			part |= 0x80  # In-place OR operation
			out += part.to_bytes(1, byteorder="big")
		else:
			out += part.to_bytes(1, byteorder="big")
			return out


def write_packet(sock, data, packet_id):
	"""
	Write a Minecraft data packet to the socket.
	
	:param sock: Stream to write to.
	:param data: Data to be written.
	:param packet_id: Numeric packet ID.
	"""
	data = encode_varint(packet_id) + data
	length = encode_varint(len(data))
	if debug: sys.stdout.write("<-- "+" ".join([hex(x | 0x100)[3:] for x in data])+"\n")
	sock.send(length + data)


def read_packet(sock) -> Tuple[int, bytes]:
	"""
	Read a packet into format (Packet ID, data).
	
	:param sock: Socket to read from.
	:return: Packet ID and corresponding data.
	"""
	packet_length = decode_varint(sock)
	packet_id = decode_varint(sock)
	data_length = packet_length - len(encode_varint(packet_id))
	data = b""
	while len(data) < data_length:
		data += sock.recv(data_length - len(data))
	if debug: sys.stdout.write("--> "+" ".join([hex(x | 0x100)[3:] for x in data])+"\n")
	return packet_id, data


class MinecraftPing:
	host: str = None
	port: int = None
	latency: float = None
	
	def __init__(self, host: str, port: int):
		"""
		Create a new MinecraftPing representing a minecraft server to ping.
		
		:param host: Hostname or IP address of the server to ping.
		:param port: Port of the minecraft server.
		"""
		self.host = host
		self.port = port
	
	def ping(self) -> Tuple[bool, Optional[str]]:
		"""
		Ping the Minecraft server, and parse its response.
		
		:return: True if the server was connected to, otherwise False with an error string.
		"""
		try:
			s = socket.create_connection((self.host, self.port), timeout=5.0)
		except Exception as e:
			return False, f"{e.__class__.__name__}: {e}"
		
		proto = encode_varint(-1)  # Protocol will be -1/unknown (which is ok)
		if len(self.host) > 32767:
			raise OverflowError("Hostname too large: >32767 bytes in size")
		host = encode_varint(len(self.host)) + self.host.encode("UTF-8")
		port = struct.pack(">H", self.port)
		state = encode_varint(1)
		write_packet(s, packet_id=0x00, data=proto+host+port+state)
		write_packet(s, packet_id=0x00, data=b"")
		
		# Send Ping packet
		write_packet(s, packet_id=0x01, data=struct.pack(">q", time.time_ns()))
		start = time.perf_counter()
		end = None
		
		# We are expecting two packets back
		for _ in range(2):
			packet_id, data = read_packet(s)
			if packet_id == 0:  # Response packet
				self._handle_response(data)
		s.close()
		# The first Ping packet shouldn't be relied on, so send another
		try:
			s = socket.create_connection((self.host, self.port), timeout=5.0)
		except:
			pass
		else:
			if debug: sys.stdout.write("Sending another Ping packet for a more accurate measurement...\n")
			write_packet(s, packet_id=0x01, data=struct.pack(">q", time.time_ns()))
			start = time.perf_counter()
			packet_id, data = read_packet(s)
			end = time.perf_counter()
			self.latency = end-start
			s.close()
		
		return True, None
	
	def _handle_response(self, data):
		"""
		Parse raw socket return data and set the attributes of the class.
		
		:param data: Raw socket data to parse.
		"""
		length, data = decode_varint(data)
		if len(data) != length:
			raise RuntimeError("Return data length mismatch")
		status = json.loads(data.decode())
		self.description = status["description"]["text"]
		self.player_limit = status["players"]["max"]
		self.player_count = status["players"]["online"]
		if self.player_count:
			self.players = [x["name"] for x in status["players"]["sample"]]
		else:
			self.players = []
		self.version = status["version"]["name"]
		self.version_id = status["version"]["protocol"]
		self.icon = status.get("favicon", "")


if __name__ == "__main__":
	if ("-s" in sys.argv) or ("--save-image" in sys.argv):
		save_image = True
		try:
			sys.argv.pop(sys.argv.index("-s"))
		except:
			pass
		try:
			sys.argv.pop(sys.argv.index("--save-image"))
		except:
			pass
	else:
		save_image = False

	if ("-d" in sys.argv) or ("--debug" in sys.argv):
		debug = True
		try:
			sys.argv.pop(sys.argv.index("-d"))
		except:
			pass
		try:
			sys.argv.pop(sys.argv.index("--debug"))
		except:
			pass
	else:
		debug = False
	
	try:
		sys.argv.pop(sys.argv.index("-h"))
	except:
		pass
	try:
		sys.argv.pop(sys.argv.index("--help"))
	except:
		pass
	
	if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
		# No arguments, print usage information
		sys.stdout.write("mcping: short and sweet Minecraft server ping tool\n")
		sys.stdout.write(f"Version {__version__}\n")
		sys.stdout.write("Usage: mcping.py <host> [port] [-ds]\n")
		sys.stdout.write("  -d, --debug       Debug mode (print raw packet IO and show protocol version)\n")
		sys.stdout.write("  -h, --help        Show this help\n")
		sys.stdout.write("  -s, --save-image  Save server thumbnail image to file\n")
		sys.stdout.write("\n")
		sys.stdout.write("Author: ntoskrnl4 <gogadgetmatthew@gmail.com>\n")
		exit()
	
	if len(sys.argv) == 2:
		host = sys.argv[1]
		if ":" in host:
			host, port = host.split(":")
			try:
				port = int(port)
			except ValueError:
				sys.stdout.write("Argument error: Non-numeric port provided")
				exit()
		else:
			port = 25565
		server = MinecraftPing(host, port)
		success, error = server.ping()
	
	if len(sys.argv) == 3:
		host = sys.argv[1]
		try:
			port = int(sys.argv[2])
		except ValueError:
			sys.stdout.write("Argument error: Non-numeric port provided\n")
			exit()
		server = MinecraftPing(host, port)
		success, error = server.ping()
	
	if not success:
		sys.stdout.write("Could not connect to server: "+error+"\n")
		exit()
	
	# todo: convert formatting codes in description to ANSI color codes
	#  (as its own function please)
	sys.stdout.write(server.description)
	sys.stdout.write("\n--------------------------------\n")
	sys.stdout.write(f"Latency: {server.latency*1000:.1f} ms\n")
	sys.stdout.write(f"Players: {server.player_count}/{server.player_limit}\n")
	if server.player_count:
		sys.stdout.write(f"Online: {', '.join(server.players)}\n")
	sys.stdout.write(f"Version: {server.version}\n")
	if debug:
		sys.stdout.write(f"Version ID: {server.version_id}\n")
	if save_image and server.icon:
		if os.path.exists("server.png"):
			answer = input("Target image file server.png exists. Overwrite? [Y/n]")[0].lower()
			if answer not in ["", "y"]:
				sys.stdout.write("Target file exists; aborting\n")
				exit()
		with open("server.png", "wb") as out:
			out.write(base64.b64decode(server.icon[22:]))
		sys.stdout.write("Server icon written to server.png\n")

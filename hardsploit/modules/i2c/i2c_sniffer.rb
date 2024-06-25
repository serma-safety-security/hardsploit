#!/usr/bin/ruby
#===================================================
#  Hardsploit API - By Opale Security
#  www.opale-security.com || www.hardsploit.io
#  License: GNU General Public License v3
#  License URI: http://www.gnu.org/licenses/gpl.txt
#===================================================

require_relative '../../Core/HardsploitAPI'
class HardsploitAPI_I2C_SNIFFER
public

	def initialize(timeout:)
		#to be sure the singleton was initialize
		HardsploitAPI.instance.connect
		self.timeout=timeout
		#i2c_SetSettings # fonction ? class ?
	end

	def timeout
		return @timeout
	end

	def timeout=(timeout)
		@timeout = timeout
	end

	def i2c_start_sniff(path:)
		packet = HardsploitAPI.prepare_packet # 0x50 Command raw communication to FPGA fifo included inside prepare_packet
		packet.push 0x55 #Command start sniffer
		#First we will try to have the first frame only, and then all frames
		HardsploitAPI.instance.sendPacket(packet)
		file = File.open(path,"wb")
		stop = FALSE
		while (stop == FALSE)
			begin
				result = HardsploitAPI.instance.receiveDATA(@timeout).bytes.to_a.drop(4)#.drop(4) #5s = time out car sniffer, assez aléatoire pour savoir quand une donnée va arriver
				p result
				file.write result.pack('C*')
			rescue LIBUSB::ERROR_TIMEOUT
				end_packet = HardsploitAPI.prepare_packet # 0x50 Command raw communication to FPGA fifo include inside prepare_packet
				end_packet.push 0xaa #Command stop sniffer
				begin
					result = HardsploitAPI.instance.sendAndReceiveDATA(end_packet,1000).drop(4) #timeout 1s
					p result
					file.write result.pack('C*')
					file.close
				end
				stop = TRUE
			end
			sleep(0.01)
		end
		p result.size
		return result
	end

	def i2c_stop_sniff
		end_packet = HardsploitAPI.prepare_packet # 0x50 Command raw communication to FPGA fifo include inside prepare_packet
		end_packet.push 0xaa #Command stop sniffer
		begin
			p result = HardsploitAPI.instance.sendAndReceiveDATA(end_packet,1000).drop(4) #timeout 1s
			p result.size
			#HardsploitAPI.instance.sendPacket(end_packet)	#We send the stop command and we wait for the last data which are not already transmitted
																						#What can we do if there is no data...
	#	rescue
	#		raise HardsploitAPI::ERROR::USB_ERROR
		end
		return result
	end
end

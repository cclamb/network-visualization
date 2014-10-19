#!/usr/bin/env ruby

require 'pcap'
require 'json'

class FlowProcessor 

	def initialize
		@_flows = {}
	end

	def add_packet(pkt)
		record = create_record pkt
		if @_flows.has_key? record then
			idx = @_flows[record]
			@_flows[record] = idx + 1
		else
			@_flows[record] = 0
		end
	end

	def create_record(pkt)
		record = {}
		if pkt.tcp?
			record[:src_port] = pkt.sport
			record[:dst_port] = pkt.dport 
		end
		if pkt.ip?
			record[:src_addr] = pkt.src
			record[:dst_addr] = pkt.dst

			# print "#{pkt.src.to_s.sub!(/\S{4}$/, '')}\n"
		end
		return record
	end

	def flows
		return @_flows
	end

	def size
		return @_flows.size
	end

end

class PacketProcessor

	def initialize
		@_cnt = 0
		@_packets = []
	end

	def add_packet(pkt)
		@_cnt = @_cnt +1
		@_packets.push(pkt)
	end

	def packets
		return @_packets
	end

	def size
		return @_cnt
	end

end

in_filename = 'data/LLS_DDOS_1.0-dmz.dump'
out_filename = 'data/dmz.json'

inp = Pcap::Capture.open_offline in_filename
flows = FlowProcessor.new
pkts = PacketProcessor.new
inp.loop(-1) do |pkt|
	print '.' if pkts.size % 10000 == 0
	flows.add_packet(pkt)
	pkts.add_packet(pkt)
end

flow_json = JSON.generate(flows.flows)

print "\nWe have a total of #{flows.size} flows over #{pkts.size} packets.\n"
#print "#{flow_json}"

File.open(out_filename, 'w') { |file| file.write(flow_json) }

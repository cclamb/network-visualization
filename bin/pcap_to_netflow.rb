#!/usr/bin/env ruby

in_filename = 'data/LLS_DDOS_1.0-dmz.dump'
out_filename = ''

inp = Pcap::Capture.open_offline in_filename
inp.loop(-1) do |pkt|
	# print "#{pkt.time} #{pkt}"
	if pkt.tcp?
		# print " (#{pkt.tcp_data_len})"
		# print " ack #{pkt.tcp_ack}" if pkt.tcp_ack?
		# print " win #{pkt.tcp_win}"
	end
	if pkt.ip?
		# print " (DF)" if pkt.ip_df?
	end
	print "\n"

end
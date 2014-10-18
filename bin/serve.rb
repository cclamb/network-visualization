#!/usr/bin/env ruby

require 'sinatra'

help = <<eos
	This is the base service for PCAP data. Currently this is hosting data from the DARPA, hosted at Lincoln Labs.
  We are currently using the circa 2000 data sets, LLDOS-1.  For more information on this data set, please see 
  http://www.ll.mit.edu/mission/communications/cyber/CSTcorpora/ideval/data/index.html.

  Currently, if you're seeing this, you're using the wrong URL.  Rather, you should use either <url>/dmz or 
  <url>/inside for either DMZ tcpdump or internal tcpdump data.
eos

in_filename   = 'data/LLS_DDOS_1.0-inside.dump'
dmz_filename  = 'data/LLS_DDOS_1.0-dmz.dump'

get '/' do
	help
end

get '/dmz' do 
  'dmz'
end

get '/inside' do
  'inside'
end
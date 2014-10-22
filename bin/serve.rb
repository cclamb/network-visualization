#!/usr/bin/env ruby

require 'sinatra'
require 'sinatra/cross_origin'

help = <<eos
	This is the base service for PCAP data. Currently this is hosting data from the DARPA, hosted at Lincoln Labs.
  We are currently using the circa 2000 data sets, LLDOS-1.  For more information on this data set, please see 
  http://www.ll.mit.edu/mission/communications/cyber/CSTcorpora/ideval/data/index.html.

  Currently, if you're seeing this, you're using the wrong URL.  Rather, you should use either <url>/dmz or 
  <url>/inside for either DMZ tcpdump or internal tcpdump data.
eos

in_filename   = 'data/inside.json'
dmz_filename  = 'data/dmz.json'

file = File.open(dmz_filename, "rb")
dmz_json = file.read
file.close

file = File.open(in_filename, "rb")
inside_json = file.read
file.close

configure do
	mime_type :json, 'application/json'
  enable :cross_origin
end

get '/' do
	help
end

get '/dmz' do 
	content_type :json
	return dmz_json
end

get '/inside' do
  	content_type :json
	return inside_json
end
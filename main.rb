lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require "awesome_print"
require "nmap_ruby"


nmap = NmapRuby::Nmap.new("--help")
ap nmap.hosts

argv = "--top-ports 1000 --open -sV -n -v 222.139.215.207-208"
#argv = "--top-ports 1000 --open -sV -n -v 222.139.215.199"
nmap = NmapRuby::Nmap.new(argv)

ap nmap.hosts
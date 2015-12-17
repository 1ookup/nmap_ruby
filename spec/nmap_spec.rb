# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'nmap_ruby'

RSpec.describe NmapRuby::Nmap do
	#describe '#scan a alive host' do
	#	it 'returns the a host abd some ports' do
	describe '#help' do
		context "with --help" do
			it 'returns the nmap_help' do
				expect(NmapRuby::Nmap.new("--help").hosts).to eq([])
			end
		end

		context "with -n -v 192.168.0.1 --help" do
			it ".hosts return the []" do
				expect(NmapRuby::Nmap.new("-n -v 192.168.0.1 --help").hosts).to eq([])
			end
		end
	end

	describe '#scan' do
		context "a alive host" do
			it "returns a host and more ports" do
				nmap = NmapRuby::Nmap.new("-n -v 192.168.1.1")
				expect(nmap.hosts.size).to eq(1)
				expect(nmap.hosts.first[:host][:host]).to eq("192.168.1.1")
				expect(nmap.hosts.first[:ports].size).to eq(2)
			end
		end

		context "a down host" do
			it "returns a host and more ports" do
				nmap = NmapRuby::Nmap.new("-n -v 192.168.1.254")
				expect(nmap.hosts).to eq([])
			end
		end
	end


end
#require "awesome_print"
module NmapRuby
  class Nmap

  	attr_reader :hosts
  	def initialize(args = nil)
  		@hosts = []

  		args = args.split(" ") unless args == nil
  		if (args.length == 0)
	      print_status("Usage: db_nmap [--save | [--help | -h]] [nmap options]")
	      return nil
	    end

	  	@arguments = []
	    while (arg = args.shift)
	      case arg
	      when "--help", '-h'
	        nmap_help
	        return
	      else
	        @arguments << arg
	      end
	    end

	    # 获取nmap 路径
	    # only linux
  		@nmap = FileUtils.find_full_path("nmap")
  		
  		# 生成xml路径
  		@xml_path_fd = Tempfile.new("nmap_#{Time.now.to_i}.xml")
  		#@xml_path_fd.close
  		@arguments.push('-oX', @xml_path_fd.path)
  		#@xml_data = nil
  		
  		# 开始扫描
  		run
  	end
=begin
  @host = [
  	{
  		:ip =>
  		:ports = > [

  		]

  		},
  ]
=end
  	
private
  	def run
  		puts "run"
      begin
        nmap_pipe = ::Open3::popen3([@nmap, 'nmap'], *@arguments)
        temp_nmap_threads = []
        temp_nmap_threads << Thread.new do |np_1|
          nmap_pipe[1].each_line do |nmap_out|
            next if nmap_out.strip.empty?
            puts("Nmap: #{nmap_out.strip}")
          end
        end

        temp_nmap_threads << Thread.new do |np_2|
          nmap_pipe[2].each_line do |nmap_err|
            next if nmap_err.strip.empty?
            puts("Nmap: '#{nmap_err.strip}'")
          end
        end

        temp_nmap_threads.map {|t| t.join rescue nil}
        nmap_pipe.each {|p| p.close rescue nil}
      rescue ::IOError
      end
      xml_data = File.read(@xml_path_fd.path)
      import_nmap_xml(xml_data)
  	end

  	
  	def nmap_help
  		puts "nmap_help"
  	end


  	def import_nmap_xml(xml_data)

  		parser = NmapRuby::NmapXMLStreamParser.new

  		# Whenever the parser pulls a host out of the nmap results, store
	    # it, along with any associated services, in the database.
	    parser.on_found_host = Proc.new { |h|
	      hobj = nil
	      #data = {:workspace => wspace}
	      data = {}
	      if (h["addrs"].has_key?("ipv4"))
	        addr = h["addrs"]["ipv4"]
	      elsif (h["addrs"].has_key?("ipv6"))
	        addr = h["addrs"]["ipv6"]
	      else
	        # Can't report it if it doesn't have an IP
	        raise RuntimeError, "At least one IPv4 or IPv6 address is required"
	      end
	      
	      #next if bl.include? addrs 				#黑名单ip 自动略过
	      
	      data[:host] = addr
	      if (h["addrs"].has_key?("mac"))
	        data[:mac] = h["addrs"]["mac"]
	      end
	      data[:state] = (h["status"] == "up") ? NmapRuby::Alive : NmapRuby::Dead
	      #data[:task] = args[:task]

	      if ( h["reverse_dns"] )
	        data[:name] = h["reverse_dns"]
	      end

	      # Only report alive hosts with ports to speak of.
	      if(data[:state] != NmapRuby::Dead)
	        if h["ports"].size > 0
=begin
	          if fix_services
	            port_states = h["ports"].map {|p| p["state"]}.reject {|p| p == "filtered"}
	            next if port_states.compact.empty?
	          end
=end
	          #yield(:address,data[:host]) if block
	          #puts "Report Host:"
	          #ap data
	          @hosts << { host: data, ports: [] }
	          #hobj = report_host(data)
	          #report_import_note(wspace,hobj)
	        end
	      end
=begin
	      if( h["os_vendor"] )
	        note = {
	          #:workspace => wspace,
	          :host => hobj || addr,
	          :type => 'host.os.nmap_fingerprint',
	          #:task => args[:task],
	          :data => {
	            :os_vendor   => h["os_vendor"],
	            :os_family   => h["os_family"],
	            :os_version  => h["os_version"],
	            :os_accuracy => h["os_accuracy"]
	          }
	        }

	        if(h["os_match"])
	          note[:data][:os_match] = h['os_match']
	        end

	        # report_note(note)
	        puts "Note: "
	        ap note
	      end

	      if (h["last_boot"])
	        report_note(
	          :workspace => wspace,
	          :host => hobj || addr,
	          :type => 'host.last_boot',
	          :task => args[:task],
	          :data => {
	            :time => h["last_boot"]
	          }
	        )
	      end

	      if (h["trace"])
	        hops = []
	        h["trace"]["hops"].each do |hop|
	          hops << {
	            "ttl"     => hop["ttl"].to_i,
	            "address" => hop["ipaddr"].to_s,
	            "rtt"     => hop["rtt"].to_f,
	            "name"    => hop["host"].to_s
	          }
	        end
	        report_note(
	          :workspace => wspace,
	          :host => hobj || addr,
	          :type => 'host.nmap.traceroute',
	          :task => args[:task],
	          :data => {
	            'port'  => h["trace"]["port"].to_i,
	            'proto' => h["trace"]["proto"].to_s,
	            'hops'  => hops
	          }
	        )
	      end
=end

	      # Put all the ports, regardless of state, into the db.
	      h["ports"].each { |p|
	        # Localhost port results are pretty unreliable -- if it's
	        # unknown, it's no good (possibly Windows-only)
	        if (
	          p["state"] == "unknown" &&
	          h["status_reason"] == "localhost-response"
	        )
	          next
	        end
	        extra = ""
	        extra << p["product"]   + " " if p["product"]
	        extra << p["version"]   + " " if p["version"]
	        extra << p["extrainfo"] + " " if p["extrainfo"]

	        data = {}
	        #data[:workspace] = wspace
=begin
	        if fix_services
	          data[:proto] = nmap_msf_service_map(p["protocol"])
	        else
	          data[:proto] = p["protocol"].downcase
	        end
=end
					data[:proto] = p["protocol"].downcase
	        data[:port]  = p["portid"].to_i
	        data[:state] = p["state"]
	        data[:host]  = hobj || addr
	        data[:info]  = extra if not extra.empty?
	        #data[:task]  = args[:task]
	        data[:name]  = p['tunnel'] ? "#{p['tunnel']}/#{p['name'] || 'unknown'}" : p['name']
	        #report_service(data)
	        #puts "Report Service:"
	       	#ap data
	       	@hosts.last[:ports] << data
	      }
=begin
	      #Parse the scripts output
	      if h["scripts"]
	        h["scripts"].each do |key,val|
	          if key == "smb-check-vulns"
	            if val =~ /MS08-067: VULNERABLE/
	              vuln_info = {
	                :workspace => wspace,
	                :task => args[:task],
	                :host =>  hobj || addr,
	                :port => 445,
	                :proto => 'tcp',
	                :name => 'MS08-067',
	                :info => 'Microsoft Windows Server Service Crafted RPC Request Handling Unspecified Remote Code Execution',
	                :refs =>['CVE-2008-4250',
	                  'BID-31874',
	                  'OSVDB-49243',
	                  'CWE-94',
	                  'MSFT-MS08-067',
	                  'MSF-Microsoft Server Service Relative Path Stack Corruption',
	                  'NSS-34476']
	              }
	              report_vuln(vuln_info)
	            end
	            if val =~ /MS06-025: VULNERABLE/
	              vuln_info = {
	                :workspace => wspace,
	                :task => args[:task],
	                :host =>  hobj || addr,
	                :port => 445,
	                :proto => 'tcp',
	                :name => 'MS06-025',
	                :info => 'Vulnerability in Routing and Remote Access Could Allow Remote Code Execution',
	                :refs =>['CVE-2006-2370',
	                  'CVE-2006-2371',
	                  'BID-18325',
	                  'BID-18358',
	                  'BID-18424',
	                  'OSVDB-26436',
	                  'OSVDB-26437',
	                  'MSFT-MS06-025',
	                  'MSF-Microsoft RRAS Service RASMAN Registry Overflow',
	                  'NSS-21689']
	              }
	              report_vuln(vuln_info)
	            end
	            # This one has NOT been  Tested , remove this comment if confirmed working
	            if val =~ /MS07-029: VULNERABLE/
	              vuln_info = {
	                :workspace => wspace,
	                :task => args[:task],
	                :host =>  hobj || addr,
	                :port => 445,
	                :proto => 'tcp',
	                :name => 'MS07-029',
	                :info => 'Vulnerability in Windows DNS RPC Interface Could Allow Remote Code Execution',
	                # Add more refs based on nessus/nexpose .. results
	                :refs =>['CVE-2007-1748',
	                  'OSVDB-34100',
	                  'MSF-Microsoft DNS RPC Service extractQuotedChar()',
	                  'NSS-25168']
	              }
	              report_vuln(vuln_info)
	            end
	          end
	        end
	      end
=end
	    }

	    REXML::Document.parse_stream(xml_data, parser)
	    @hosts
  	end

  end
end

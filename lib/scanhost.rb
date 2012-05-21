# This is the Finding Class, specifies all attributes of a finding
class Scanhost

	attr_accessor :hostname, :ipaddress, :hostname_clean, :operatingsystem, :findings, :msfindings

	def initialize(host)
		self.findings = Array.new
		self.msfindings = Array.new
		self.hostname = host.dns_name
		self.ipaddress = host.ip
		self.hostname_clean = self.hostname.split(".")[0].to_s.upcase
		SCANHOSTNAMES << self.hostname
		return self
	end


	def self.add_os(hostname, os, hostslist)
		hostslist.each do |ahost|
			if ahost.hostname == hostname
				ahost.operatingsystem = os
			end
		end
	end


	def self.add_finding_to_host(host, event, args)
	 	SCANHOSTS.each do |scanhost|
		 	if scanhost.ipaddress == host.ip
			 	scanhost.findings << event
			end
		end
	end


	def self.hostexists(hostname)
		if SCANHOSTNAMES.include?(hostname)
			return true
		else
			return false
		end
	end


	def self.display_host_info(host, args)
		lowfindings = Array.new
		highfindings = Array.new
		mediumfindings = Array.new
		host.findings.each do |finding|	 	
	 		if finding.severity.in_words.to_s.split(" ")[0].to_s.upcase == "HIGH"
	    		highfindings << finding
	   		elsif finding.severity.in_words.to_s.split(" ")[0].to_s.upcase == "MEDIUM"
	     		mediumfindings << finding
	   		elsif finding.severity.in_words.to_s.split(" ")[0].to_s.upcase == "LOW"
	     		lowfindings << finding
     		end
     	end
	 		hostreport = "\r\nHostname: "  + host.hostname + "\r\n"
	 		hostreport += "IP Address: " + host.ipaddress + "\r\n"
	 		hostreport += "Operating System: " + host.operatingsystem + "\r\n"
	 		hostreport += "Total Findings: " + host.findings.length.to_s + "\r\n"
	 		hostreport += "  Highs: " + highfindings.length.to_s + "\r\n"
	 		hostreport += "  Mediums: " + mediumfindings.length.to_s + "\r\n"
	 		hostreport += "  Lows: " + lowfindings.length.to_s + "\r\n"
	 		if args[:severity]
				hostreport += "\r\n"
 				hostreport += "\t#{args[:severity].to_s.upcase} Findings:\r\n"
	 			hostreport += "\tPlugin" + "\t- " + "Finding Name\r\n"
	 			hostreport += "\t---------------\r\n"
		 		host.findings.each do |finding|
		   			if finding.severity.in_words.to_s.split(" ")[0].to_s.upcase == args[:severity].to_s.upcase
	   					hostreport += "\t" + finding.plugin_id.to_s + "\t- " + finding.name.to_s + "\r\n" unless hostreport.include?(finding.name.to_s)
	   				end
	 			end
	 		end
	 		hostreport += "\r\n"
	 	return hostreport
	end


	def self.display_all_hosts(hosts, options)
		hosts.each do |host|
			if options[:severity]			
				puts host.hostname_clean + "\t" + host.ipaddress +  "\t" + host.operatingsystem.to_s + " - " + host.findings.length.to_s + " #{options[:severity].to_s.upcase} Findings" + "\r\n"
			else
			 	puts host.hostname_clean + "\t" + host.ipaddress +  "\t" + host.operatingsystem.to_s + " - " + host.findings.length.to_s + " Total Findings" + "\r\n"
			end
		end
	end

end


def match_hosts_to_findings(file, args)
		Nessus::Parse.new(file) do |scan|
		scan.each_host do |host|
			host.each_event do |event|
				Scanhost.add_finding_to_host(host, event, args) unless event.name.to_s =~ /MS\d{2}\-\d{3}/
			end
		end
	end
end


def generate_host_summary(hosts, args)
	hosts.each do |host|
		if host.ipaddress == args[:hostname].chomp
			puts Scanhost.display_host_info(host, args)
		end
	end
end

def get_os(event, host)
	if event.plugin_id == 11936
		os = event.data.split("\n")
		os = os[0].to_s.split(":")
		return os[6].to_s.split("\\")[0]
	end
end
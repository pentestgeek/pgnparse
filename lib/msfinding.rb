class Msfinding

	attr_accessor :msid, :url, :is_superseded

	def initialize(msfinding)
		self.msid = msfinding.split(" ")[1]
		self.url = msfinding.split(" ")[3]
		self.is_superseded = false
		return self
	end

	def self.generate_ms_summary(hosts)
		hosts.each do |host|
			if host.msfindings.length > 0
				puts host.hostname + " - " + host.ipaddress + " - " + "Missing #{host.msfindings.length.to_s} MS Patches" +  "\r\n"
			end
		end
	end

end


def parse_ms_findings(hosts)
	hosts.each do |host|
		host.findings.each do |finding|
			if finding.plugin_id == 38153
				add_ms_finding(finding, host)
			end
		end
	end
	Msfinding.generate_ms_summary(SCANHOSTS)
end

def add_ms_finding(event, host)
	findingblock = event.data.split("\\n\\n")[10]
	findingblock.to_s.split("\\n").each do |line|
		host.msfindings << Msfinding.new(line)
	end
end


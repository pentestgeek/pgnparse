#Class to define Finding characterstics and attributes
class Finding

	attr_accessor :name, :severity, :pluginid, :data, :count, :ipaddresses, :hostnames

	def initialize(event, host)
		self.ipaddresses = Array.new
		self.hostnames = Array.new
		self.pluginid = event.plugin_id
		self.name = event.name
		self.data = event.data
		self.severity = event.severity.in_words.split(" ")[0].to_s.upcase
		self.count = 1
		CREATEDFINDINGS << self.pluginid
		return self
	end


	def self.append_to_finding(event, host)
		FINDINGS.each do |finding|
			if finding.pluginid == event.plugin_id
				finding.count = finding.count + 1
				finding.ipaddresses << host.ip
				finding.hostnames << host.dns_name.split(".")[0].to_s.upcase
			end
		end
	end


	def self.finding_exists(pluginid)
		if CREATEDFINDINGS.include?(pluginid)
			return true
		else
			return false
		end
	end


	def self.display_finding(finding, args)
		if args[:severity]
			puts finding.pluginid.to_s + " - " + finding.name + " - " + finding.count.to_s + " Systems" if finding.severity.to_s.upcase == args[:severity].to_s.upcase
		else	
			puts finding.pluginid.to_s + " - " + finding.name + " - " + finding.count.to_s + " Systems"
		end
	end


	def self.display_all_findings(findings, args)
		findings.each do |finding|
			display_finding(finding, args)
		end
	end


	def self.display_finding_info(finding)
		summary = finding.data.split("\\n\\n")
		findingreport = finding.name + "\r\n\r\n"
		summary.each do |line|
			findingreport += line.chomp + "\r\n\r\n"
		end
		return findingreport
	end

end


def add_finding(event, host)
	if Finding.finding_exists(event.plugin_id) == false
		FINDINGS.push(Finding.new(event, host))
	else
		Finding.append_to_finding(event, host)
	end
end


def get_plugin_info(findingid)
	FINDINGS.each do |finding|
		if finding.pluginid.to_s == findingid.to_s
			puts Finding.display_finding_info(finding)
		end
	end
end
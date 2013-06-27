##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'IIS ISAPI Enabled Checker',
			'Description' => 'Detects ISAPI enabled on IIS servers',
			'Author'       => 'connection <hacktalk@hacktalk.net>',
			'License'     => MSF_LICENSE,
			'Version'	=> "1.0"
		)

		register_options(
			[
				OptString.new("PATH", [true, "Path to use", '/x.printer']),
			], self.class)
	end

	def run_host(target_host)

		begin
			res = send_request_cgi({
				'uri'          => normalize_uri(datastore['PATH']),
				'method'       => 'GET',
				'data'	=>	'',
				'ctype'   => 'text/xml',
				'version' => '1.0',
			}, 10)


			if res and res.body
				# short regex
				intipregex = /<b>.*Error.*web.*<\/b>/i

				#print_status("#{res.body}")

				result = res.body.scan(intipregex).uniq


				result.each do |addr|
					print_status("IIS ISAPI Enabled (#{target_host})")

					report_note(
						:host	=> target_host,
						:proto => 'tcp',
						:sname => (ssl ? 'https' : 'http'),
						:port	=> rport,
						:type	=> 'INTERNAL_IP',
						:data	=> 'ISAPI Extensions Enabled on #{target_host}'
					)
				end
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

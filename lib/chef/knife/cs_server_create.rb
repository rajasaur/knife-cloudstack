#
# Author:: Ryan Holmes (<rholmes@edmunds.com>)
# Author:: Sander Botman (<sbotman@schubergphilis.com>)
# Copyright:: Copyright (c) 2011 Edmunds, Inc.
# Copyright:: Copyright (c) 2013 Sander Botman.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'chef/knife/cs_base'

module KnifeCloudstack
  class CsServerCreate < Chef::Knife

    include Chef::Knife::KnifeCloudstackBase

    # Seconds to delay between detecting ssh and initiating the bootstrap
    BOOTSTRAP_DELAY = 20

    # Seconds to wait between ssh pings
    SSH_POLL_INTERVAL = 10

    deps do
      require 'chef/knife/bootstrap'
      require 'socket'
      require 'net/ssh/multi'
      require 'chef/knife'
      require 'chef/knife/bootstrap'
      require 'chef/json_compat'
      require 'knife-cloudstack/connection'
      require 'httpclient'
      Chef::Knife::Bootstrap.load_deps
    end

    banner "knife cs server create [SERVER_NAME] (options)"

    option :cloudstack_service,
           :short => "-S SERVICE",
           :long => "--service SERVICE",
           :description => "The CloudStack service offering name",
           :proc => Proc.new { |o| Chef::Config[:knife][:cloudstack_service] = o },
           :default => "M"

    option :cloudstack_template,
           :short => "-T TEMPLATE",
           :long => "--template TEMPLATE",
           :description => "The CloudStack template for the server",
           :proc => Proc.new { |t| Chef::Config[:knife][:cloudstack_template] = t }

    option :cloudstack_zone,
           :short => "-Z ZONE",
           :long => "--zone ZONE",
           :description => "The CloudStack zone for the server",
           :proc => Proc.new { |z| Chef::Config[:knife][:cloudstack_zone] = z }

    option :cloudstack_networks,
           :short => "-W NETWORKS",
           :long => "--networks NETWORK",
           :description => "Comma separated list of CloudStack network names",
           :proc => lambda { |n| n.split(',').map {|sn| sn.strip}} ,
           :default => []

    option :cloudstack_hypervisor,
           :long => '--cloudstack-hypervisor HYPERVISOR',
           :description => "The CloudStack hypervisor type for the server"

    option :cloudstack_password,
           :long => "--cloudstack-password",
           :description => "Enables auto-generated passwords by Cloudstack",
           :boolean => true

    option :public_ip,
           :long => "--[no-]public-ip",
           :description => "Allocate a public IP for this server",
           :boolean => true,
           :default => true

    option :chef_node_name,
           :short => "-N NAME",
           :long => "--node-name NAME",
           :description => "The Chef node name for your new node"

    option :ssh_user,
           :short => "-x USERNAME",
           :long => "--ssh-user USERNAME",
           :description => "The ssh username"

    option :ssh_password,
           :short => "-P PASSWORD",
           :long => "--ssh-password PASSWORD",
           :description => "The ssh password"

    option :ssh_port,
           :long => "--ssh-port PORT",
           :description => "The ssh port",
           :default => "22"

    option :identity_file,
           :short => "-i IDENTITY_FILE",
           :long => "--identity-file IDENTITY_FILE",
           :description => "The SSH identity file used for authentication"

    option :prerelease,
           :long => "--prerelease",
           :description => "Install the pre-release chef gems"

    option :bootstrap_version,
           :long => "--bootstrap-version VERSION",
           :description => "The version of Chef to install",
           :proc => Proc.new { |v| Chef::Config[:knife][:bootstrap_version] = v }

    option :distro,
           :short => "-d DISTRO",
           :long => "--distro DISTRO",
           :description => "Bootstrap a distro using a template",
           :proc => Proc.new { |d| Chef::Config[:knife][:distro] = d },
           :default => "chef-full"

    option :template_file,
           :long => "--template-file TEMPLATE",
           :description => "Full path to location of template to use",
           :proc => Proc.new { |t| Chef::Config[:knife][:template_file] = t },
           :default => false

    option :run_list,
           :short => "-r RUN_LIST",
           :long => "--run-list RUN_LIST",
           :description => "Comma separated list of roles/recipes to apply",
           :proc => lambda { |o| o.split(/[\s,]+/) },
           :default => []

    option :no_host_key_verify,
           :long => "--no-host-key-verify",
           :description => "Disable host key verification",
           :boolean => true,
           :default => false

    option :bootstrap,
           :long => "--[no-]bootstrap",
           :description => "Disable Chef bootstrap",
           :boolean => true,
           :default => true

    option :port_rules,
           :short => "-p PORT_RULES",
           :long => "--port-rules PORT_RULES",
           :description => "Comma separated list of port forwarding rules, e.g. '25,53:4053,80:8080:TCP'",
           :proc => lambda { |o| o.split(/[\s,]+/) },
           :default => []

    option :static_nat,
           :long => '--static-nat',
           :description => 'Support Static NAT',
           :boolean => true,
           :default => false

    option :ipfwd_rules,
           :long => "--ipfwd-rules PORT_RULES",
           :description => "Comma separated list of ip forwarding rules, e.g. '1024:10000:TCP,1024:2048,22'",
           :proc => lambda { |o| o.split(/[\s,]+/) },
           :default => []

    option :fw_rules,
           :short => "-f PORT_RULES",
           :long => "--fw-rules PORT_RULES",
           :description => "Comma separated list of firewall rules, e.g. 'TCP:192.168.0.0/16:1024:65535,TCP::22,UDP::123,ICMP'",
           :proc => lambda { |o| o.split(/[\s,]+/) },
           :default => []

    option :bootstrap_protocol,
           :long => "--bootstrap-protocol protocol",
           :description => "Protocol to bootstrap servers. options: ssh",
           :default => "ssh"

    option :fqdn,
           :long => '--fqdn',
           :description => "FQDN which Kerberos Understands (only for Windows Servers)"

    def run
      validate_base_options

      Chef::Log.debug("Validate hostname and options")
      hostname = @name_args.first
      unless /^[a-zA-Z0-9][a-zA-Z0-9-]*$/.match hostname then
        ui.error "Invalid hostname. Please specify a short hostname, not an fqdn (e.g. 'myhost' instead of 'myhost.domain.com')."
        exit 1
      end
      validate_options

      $stdout.sync = true

      Chef::Log.info("Creating instance with
        service : #{locate_config_value(:cloudstack_service)}
        template : #{locate_config_value(:cloudstack_template)}
        zone : #{locate_config_value(:cloudstack_zone)}
        project: #{locate_config_value(:cloudstack_project)}
        network: #{locate_config_value(:cloudstack_networks)}")

      print "\n#{ui.color("Waiting for Server to be created", :magenta)}"
      params = {} 
      params['hypervisor'] = locate_config_value(:cloudstack_hypervisor) if locate_config_value(:cloudstack_hypervisor)

      server = connection.create_server(
          hostname,
          locate_config_value(:cloudstack_service),
          locate_config_value(:cloudstack_template),
          locate_config_value(:cloudstack_zone),
          locate_config_value(:cloudstack_networks),
          params
      )

      public_ip = find_or_create_public_ip(server, connection)

      object_fields = []
      object_fields << ui.color("Name:", :cyan)
      object_fields << server['name'].to_s
      object_fields << ui.color("Name:", :cyan) if locate_config_value(:cloudstack_password)
      object_fields << server['password'] if locate_config_value(:cloudstack_password)
      object_fields << ui.color("Public IP:", :cyan)
      object_fields << public_ip

      puts "\n"
      puts ui.list(object_fields, :uneven_columns_across, 2)
      puts "\n"

      return unless config[:bootstrap]

      if @bootstrap_protocol == 'ssh'
        print "\n#{ui.color("Waiting for sshd", :magenta)}"

        print(".") until is_ssh_open?(public_ip) {
          sleep BOOTSTRAP_DELAY
          puts "\n"
        }
      end

      object_fields = []
      object_fields << ui.color("Name:", :cyan)
      object_fields << server['name'].to_s
      object_fields << ui.color("Public IP:", :cyan)
      object_fields << public_ip
      object_fields << ui.color("Environment:", :cyan)
      object_fields << (config[:environment] || '_default')
      object_fields << ui.color("Run List:", :cyan)
      object_fields << config[:run_list].join(', ')

      puts "\n"
      puts ui.list(object_fields, :uneven_columns_across, 2)
      puts "\n"

      bootstrap(server, public_ip).run
    end

    def fetch_server_fqdn(ip_addr)
        require 'resolv'
        Resolv.getname(ip_addr)
    end

    def validate_options
      unless locate_config_value :cloudstack_template
        ui.error "Cloudstack template not specified"
        exit 1
      end

      unless locate_config_value :cloudstack_service
        ui.error "Cloudstack service offering not specified"
        exit 1
      end
      if config[:bootstrap]
        if locate_config_value(:bootstrap_protocol) == 'ssh'
          identity_file = locate_config_value :identity_file
          ssh_user = locate_config_value :ssh_user
          ssh_password = locate_config_value :ssh_password
          unless identity_file || (ssh_user && ssh_password) || locate_config_value(:cloudstack_password)
            ui.error("You must specify either an ssh identity file or an ssh user and password")
            exit 1
          end
          @bootstrap_protocol = 'ssh'
        end
      end
    end

    def find_or_create_public_ip(server, connection)
      nic = connection.get_server_default_nic(server) || {}
      #puts "#{ui.color("Not allocating public IP for server", :red)}" unless config[:public_ip]
      if (config[:public_ip] == false)
        nic['ipaddress']
      else
        puts("\nAllocate ip address, create forwarding rules")
        ip_address = connection.associate_ip_address(server['zoneid'], locate_config_value(:cloudstack_networks))
        puts("\nAllocated IP Address: #{ip_address['ipaddress']}")
        Chef::Log.debug("IP Address Info: #{ip_address}")

        if locate_config_value :static_nat
          Chef::Log.debug("Enabling static NAT for IP Address : #{ip_address['ipaddress']}")
          connection.enable_static_nat(ip_address['id'], server['id'])
        end
        create_port_forwarding_rules(ip_address, server['id'], connection)
        create_ip_forwarding_rules(ip_address, connection)
        create_firewall_rules(ip_address, connection)
        ip_address['ipaddress']
      end
    end

    def create_port_forwarding_rules(ip_address, server_id, connection)
      rules = locate_config_value(:port_rules)
      if config[:bootstrap]
        if @bootstrap_protocol == 'ssh'
          rules += ["#{locate_config_value(:ssh_port)}"] #SSH Port
        elsif @bootstrap_protocol == 'winrm'
          rules +=[locate_config_value(:winrm_port)]
        else
          puts("\nUnsupported bootstrap protocol : #{@bootstrap_protocol}")
          exit 1
        end
      end
      return unless rules
      rules.each do |rule|
        args = rule.split(':')
        public_port = args[0]
        private_port = args[1] || args[0]
        protocol = args[2] || "TCP"
        if locate_config_value :static_nat
          Chef::Log.debug("Creating IP Forwarding Rule for
            #{ip_address['ipaddress']} with protocol: #{protocol}, public port: #{public_port}")
          connection.create_ip_fwd_rule(ip_address['id'], protocol, public_port, public_port)
        else
          Chef::Log.debug("Creating Port Forwarding Rule for #{ip_address['id']} with protocol: #{protocol},
            public port: #{public_port} and private port: #{private_port} and server: #{server_id}")
          connection.create_port_forwarding_rule(ip_address['id'], private_port, protocol, public_port, server_id)
        end
      end
    end

    def create_ip_forwarding_rules(ip_address, connection)
      rules = locate_config_value(:ipfwd_rules)
      return unless rules
      rules.each do |rule|
        args = rule.split(':')
        startport = args[0]
        endport = args[1] || args[0]
        protocol = args[2] || "TCP"
        if locate_config_value :static_nat
          Chef::Log.debug("Creating IP Forwarding Rule for
              #{ip_address['ipaddress']} with protocol: #{protocol}, startport: #{startport}, endport: #{endport}")
          connection.create_ip_fwd_rule(ip_address['id'], protocol, startport, endport)
        end
      end
    end

    def create_firewall_rules(ip_address, connection)
      rules = locate_config_value(:fw_rules)
      return unless rules
      icmptype={
        '0' => {'code' => [0]},
        '8' => {'code' => [0]},
        '3' => {'code' => [0, 1]}
      }
      rules.each do |rule|
        args = rule.split(':')
        protocol = args[0]
        cidr_list = (args[1].nil? || args[1].length == 0) ? "0.0.0.0/0" : args[1]
        startport = args[2]
        endport = args[3] || args[2]
        if protocol == "ICMP"
          icmptype.each do |type, value|
            value['code'].each do |code_id|
              Chef::Log.debug("Creating Firewall Rule for
                #{ip_address['ipaddress']} with protocol: #{protocol}, icmptype: #{type}, icmpcode: #{code_id}, cidrList: #{cidr_list}")
              connection.create_firewall_rule(ip_address['id'], protocol, type, code_id, cidr_list)
            end
          end
        else
          Chef::Log.debug("Creating Firewall Rule for
            #{ip_address['ipaddress']} with protocol: #{protocol}, startport: #{startport}, endport: #{endport}, cidrList: #{cidr_list}")
          connection.create_firewall_rule(ip_address['id'], protocol, startport, endport, cidr_list)
        end
      end
    end

    #noinspection RubyArgCount,RubyResolve
    def is_ssh_open?(ip)
      s = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      sa = Socket.sockaddr_in(locate_config_value(:ssh_port), ip)

      begin
        s.connect_nonblock(sa)
      rescue Errno::EINPROGRESS
        resp = IO.select(nil, [s], nil, 1)
        if resp.nil?
          sleep SSH_POLL_INTERVAL
          return false
        end

        begin
          s.connect_nonblock(sa)
        rescue Errno::EISCONN
          Chef::Log.debug("sshd accepting connections on #{ip}")
          yield
          return true
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
          sleep SSH_POLL_INTERVAL
          return false
        end
      ensure
        s && s.close
      end
    end

    def bootstrap(server, public_ip)
      Chef::Log.debug("Linux Bootstrapping")
      bootstrap_for_node(server, public_ip)
    end

    def bootstrap_common_params(bootstrap)
      bootstrap.config[:run_list] = config[:run_list]
      bootstrap.config[:prerelease] = config[:prerelease]
      bootstrap.config[:bootstrap_version] = locate_config_value(:bootstrap_version)
      bootstrap.config[:distro] = locate_config_value(:distro)
      bootstrap.config[:template_file] = locate_config_value(:template_file)
      bootstrap
    end

    def bootstrap_for_node(server,fqdn)
      bootstrap = Chef::Knife::Bootstrap.new
      bootstrap.name_args = [fqdn]
      if locate_config_value(:cloudstack_password)
        bootstrap.config[:ssh_user] = locate_config_value(:ssh_user) || 'root'
      else
        bootstrap.config[:ssh_user] = locate_config_value(:ssh_user)
      end
      locate_config_value(:cloudstack_password) ? bootstrap.config[:ssh_password] = server['password'] : bootstrap.config[:ssh_password] = locate_config_value(:ssh_password)
      bootstrap.config[:ssh_port] = locate_config_value(:ssh_port) || 22
      bootstrap.config[:identity_file] = locate_config_value(:identity_file)
      bootstrap.config[:chef_node_name] = locate_config_value(:chef_node_name) || server["name"]
      bootstrap.config[:use_sudo] = true unless locate_config_value(:ssh_user) == 'root'
      bootstrap.config[:environment] = locate_config_value(:environment)

      # may be needed for vpc_mode
      bootstrap.config[:host_key_verify] = config[:host_key_verify]
      bootstrap_common_params(bootstrap)
    end

  end
end

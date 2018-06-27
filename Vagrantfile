Vagrant.configure('2') do |config|
  [1].each do |i|
    config.vm.define "knot#{i}" do |node|
      node.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"
      node.vm.box = 'ubuntu/xenial64'
      node.vm.host_name = "knot#{i}.example.com."

      h_port = 5350 + i
      node.vm.network 'forwarded_port', guest: 53, host: h_port, protocol: 'tcp'
      node.vm.network 'forwarded_port', guest: 53, host: h_port, protocol: 'udp' 

      node.vm.provision 'shell', inline: 'wget https://apt.puppetlabs.com/puppet5-release-trusty.deb'
      node.vm.provision 'shell', inline: 'dpkg -i puppet5-release-trusty.deb'
      node.vm.provision 'shell', inline: 'apt-get update'
      node.vm.provision 'shell', inline: 'apt-get -y upgrade'
      node.vm.provision 'shell', inline: 'apt-get install -y puppet-agent'

      node.vm.provision :puppet do |puppet|
        puppet.environment = 'production'
        puppet.environment_path = 'puppet/environments'
        puppet.hiera_config_path = 'puppet/hiera.yaml'
        puppet.module_path = 'puppet/modules'
      end
    end
  end
end
# vim: set syntax=ruby:

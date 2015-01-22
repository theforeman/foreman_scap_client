require 'yaml'
require 'tmpdir'
require 'net/http'
require 'net/https'
require 'uri'

module ForemanScapClient
  CONFIG_FILE = '/etc/foreman_scap_client/config.yaml'

  class Client
    def run(policy_id)
      @policy_id = policy_id

      Dir.mktmpdir do |dir|
        @tmp_dir = dir
        scan
        upload
      end
    end

    private

    def config
      @config ||= YAML.load_file(CONFIG_FILE)
    rescue => e
      puts 'Config file could not be loaded'
      puts e.message
      exit(1)
    end

    def scan
      puts "DEBUG: running: " + scan_command
      result = `#{scan_command}`
      if $?.success? || $?.exitstatus == 2
        @report = results_path
      else
        puts 'Scan failed'
        puts result
        exit(2)
      end
    end

    def results_path
      "#{@tmp_dir}/results.xml"
    end

    def scan_command
      if config[@policy_id] && config[@policy_id][:profile] && !config[@policy_id][:profile].empty?
        profile = "--profile #{config[@policy_id][:profile]}"
      else
        profile = ''
      end
      "oscap xccdf eval #{profile} --results-arf #{results_path} #{config[@policy_id][:content_path]}"
    end

    def upload
      uri = URI.parse(upload_uri)
      puts "Uploading results to #{uri}"
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = true
      https.verify_mode = OpenSSL::SSL::VERIFY_PEER
      https.ca_file = config[:ca_file]
      begin
        https.cert = OpenSSL::X509::Certificate.new File.read(config[:host_certificate])
        https.key = OpenSSL::PKey::RSA.new File.read(config[:host_private_key])
      rescue StandardError => e
        puts 'Unable to load certs'
        puts e.message
        exit(3)
      end

      request = Net::HTTP::Put.new uri.path
      request.body = File.read(results_path)
      request['Content-Type'] = 'text/xml'
      request['Content-Encoding'] = 'x-bzip2'
      begin
        res = https.request(request)
        res.value
      rescue StandardError => e
        puts res.body if res
        puts "Upload failed: #{e.message}"
        exit(4)
      end
    end

    def upload_uri
      foreman_proxy_uri + "/compliance/arf/#{@policy_id}"
    end

    def foreman_proxy_uri
      foreman_proxy_fqdn = config[:server]
      foreman_proxy_port = config[:port]
      "https://#{foreman_proxy_fqdn}:#{foreman_proxy_port}"
    end
  end
end

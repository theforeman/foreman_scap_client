require 'rubygems' if RUBY_VERSION.start_with? '1.8'
require 'yaml'
require 'tmpdir'
require 'net/http'
require 'net/https'
require 'uri'
require 'open-uri'
require 'open3'
require 'json'

module ForemanScapClient
  CONFIG_FILE = '/etc/foreman_scap_client/config.yaml'

  class Client
    attr_reader :config, :policy_id, :tailored

    def run(policy_id)
      @policy_id = policy_id
      load_config
      ensure_scan_file
      ensure_tailoring_file
      Dir.mktmpdir do |dir|
        @tmp_dir = dir
        scan
        bzip
        upload
      end
    end

    private

    def warn_proxy_not_supported
      puts 'Configuration for HTTP(S) proxy found but not supported for ruby 1.8' if http_proxy_uri
    end

    def load_config
      @config ||= YAML.load_file(CONFIG_FILE)
      ensure_policy_exist
      @tailored = @config[policy_id][:tailoring_path] && !@config[policy_id][:tailoring_path].empty?
    rescue => e
      puts 'Config file could not be loaded'
      puts e.message
      exit(1)
    end

    def scan
      puts "DEBUG: running: " + scan_command

      if RUBY_VERSION.start_with? '1.8'
        legacy_run_scan
      else
        run_scan
      end
    end

    def run_scan
      stdout_str, error_str, result = Open3.capture3(scan_command_env_vars, scan_command)
      if result.success? || result.exitstatus == 2
        puts error_str.split("\n").select { |item| item.start_with? 'WARNING:' }.join("\n")
        @report = results_path
      else
        puts 'Scan failed'
        puts stdout_str
        puts error_str
        exit(2)
      end
    end

    def legacy_run_scan
      warn_proxy_not_supported
      result = `#{scan_command}`

      if $?.success? || $?.exitstatus == 2
        @report = results_path
      else
        puts 'Scan failed'
        puts result
        exit(2)
      end
    end

    def scan_command_env_vars
      if http_proxy_uri
        {
          'HTTP_PROXY'  => http_proxy_uri,
          'HTTPS_PROXY' => http_proxy_uri
        }
      else
        {}
      end
    end

    def http_proxy_uri
      return nil unless config[:http_proxy_server] && config[:http_proxy_port]
      http_proxy_server = config[:http_proxy_server]
      http_proxy_port   = config[:http_proxy_port]
      "http://#{http_proxy_server}:#{http_proxy_port}"
    end

    def results_path
      "#{@tmp_dir}/results.xml"
    end

    def results_bzip_path
      "#{results_path}.bz2"
    end

    def scan_command
      if config[@policy_id] && config[@policy_id][:profile] && !config[@policy_id][:profile].empty?
        profile = "--profile #{config[@policy_id][:profile]}"
      else
        profile = ''
      end
      fetch_remote_resources = if config[:fetch_remote_resources]
                                 '--fetch-remote-resources'
                               else
                                 ''
                               end
      "oscap xccdf eval #{fetch_remote_resources} #{profile} #{tailoring_subcommand} --results-arf #{results_path} #{config[@policy_id][:content_path]}"
    end

    def tailoring_subcommand
      tailored ? "--tailoring-file #{config[policy_id][:tailoring_path]}" : ""
    end

    def bzip_command
      "/usr/bin/env bzip2 #{results_path}"
    end

    def bzip
      puts 'DEBUG: running: ' + bzip_command
      result = `#{bzip_command}`
      if !$?.success?
        puts 'bzip failed'
        puts results
        exit(2)
      end
    end

    def upload
      uri = URI.parse(upload_uri)
      puts "Uploading results to #{uri}"
      https = generate_https_object(uri)
      request = Net::HTTP::Post.new uri.path
      request.body = File.read(results_bzip_path)
      request['Content-Type'] = 'text/xml'
      request['Content-Encoding'] = 'x-bzip2'
      begin
        res = https.request(request)
        value = res.value
        foreman_upload_result res
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

    def generate_https_object(uri)
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
      https
    end

    def ensure_policy_exist
      if config[@policy_id].nil?
        puts "Policy id #{@policy_id} not found."
        exit(1)
      end
    end

    def ensure_file(dir, download_path, type_humanized)
      return if File.exist?(config[policy_id][dir])
      puts "File #{config[policy_id][dir]} is missing. Downloading it from proxy."
      begin
        FileUtils.mkdir_p(File.dirname(config[policy_id][dir]))
        uri = URI.parse(download_uri(config[policy_id][download_path]))
        puts "Download #{type_humanized} xml from: #{uri}"
        request = generate_https_object(uri).get(uri.path)
        request.value
        ds_content_xml = request.body
        open(config[policy_id][dir], 'wb') do |file|
          file << ds_content_xml
        end
      rescue StandardError => e
        puts "#{type_humanized} is missing and download failed with error: #{e.message}"
        exit(5)
      end
    end

    def ensure_scan_file
      ensure_file :content_path, :download_path, "SCAP content"
    end

    def ensure_tailoring_file
      return unless tailored
      ensure_file :tailoring_path, :tailoring_download_path, "Tailoring file"
    end

    def download_uri(download_path)
      foreman_proxy_uri + "#{download_path}"
    end

    def foreman_upload_result(response)
      begin
        print_upload_result JSON.parse(response.body)
      rescue StandardError => e
        # rescue and print nothing if older proxy version does not respond with json we expect
      end
    end

    def print_upload_result(parsed)
      if parsed['id']
        puts "Report uploaded, report id: #{parsed['id']}"
      else
        puts "Report not uploaded from proxy to Foreman server, cause: #{parsed['result']}"
      end
    end
  end
end

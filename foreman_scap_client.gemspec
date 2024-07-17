# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'foreman_scap_client/version'

Gem::Specification.new do |spec|
  spec.name          = "foreman_scap_client"
  spec.version       = ForemanScapClient::VERSION
  spec.authors       = ["Marek Hulan", "Šimon Lukašík", "Shlomi Zadok"]
  spec.email         = ["mhulan@redhat.com", "slukasik@redhat.com", "szadok@redhat.com"]
  spec.summary       = %q{Client script that runs openscap scan and uploads the result to foreman proxy}
  spec.description   = %q{Client script that runs openscap scan and uploads the result to foreman proxy}
  spec.homepage      = "https://github.com/theforeman/foreman_scap_client"
  spec.license       = "GPL-3.0"

  spec.files         = Dir["{bin,config,lib}/**/*", "LICENSE", "README.md"]
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.test_files    = Dir["test/**/*"]
  spec.require_paths = ["lib"]

  spec.requirements = 'bzip2'
  spec.add_dependency 'json'

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake", "~> 10.0"
end

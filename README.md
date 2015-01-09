# ForemanScapClient

Client script that runs openscap scan and uploads the result to foreman proxy.
It's usually executed by cron.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'foreman_scap_client'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install foreman_scap_client

Dependencies
    * openscap-utils

## Configuration

Configuration file must be created at /etc/foreman_scap_client/config.yaml
You can use config/config.yaml.example as an example. Also you
may be interested in puppet-openscap module that can configure this client.

## Usage

To run a openscap scan and upload a result you run following command

  # foreman_scap_client 1

This will load content file and uses a profile based on policy number 1
specified in config.yaml.

## Contributing

1. Fork it ( https://github.com/OpenSCAP/foreman_scap_client/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

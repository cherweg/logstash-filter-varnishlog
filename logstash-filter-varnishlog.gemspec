Gem::Specification.new do |s|
  s.name          = 'logstash-filter-varnishlog'
  s.version       = '0.2.1'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = 'A logstash plugin reading varnishlog output'
  s.description   = 'logstash filter plugin reading varnishlog grouped by id'
  s.homepage      = 'https://github.com/cherweg/logstash-filter-varnishlog'
  s.authors       = ['Christian Herweg']
  s.email         = 'christian.herweg@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end

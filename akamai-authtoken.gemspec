Gem::Specification.new do |s|
  s.name        = 'akamai-authtoken'
  s.version     = '0.4.1'
  s.date        = '2017-03-17'
  s.summary     = 'Akamai Authorization Token for Ruby'
  s.description = 'Akamai-AuthToken is Akamai Authorization Token for Ruby 2.0+'
  s.authors     = ['Astin Choi']
  s.email       = 'achoi@akamai.com'
  s.files       = ['lib/akamai/authtoken.rb']
  s.homepage    = 'https://github.com/AstinCHOI/AkamaiAuthToken-Ruby'
  s.license     = 'Apache'
  s.required_ruby_version = '>= 2.0'

  s.test_files    = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths = ["lib"]

  s.add_development_dependency "bundler", "~> 1.3"
  s.add_development_dependency "rake"
  s.add_development_dependency "rspec"
  s.add_development_dependency "pry"
end

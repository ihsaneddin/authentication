require_relative "lib/auth/version"

Gem::Specification.new do |spec|
  spec.name        = "auth"
  spec.version     = Auth::VERSION
  spec.authors     = [""]
  spec.email       = ["ihsaneddin@gmail.com"]
  spec.homepage    = "https://github.com/ihsaneddin"
  spec.summary     = "Summary of Auth."
  spec.description = "Description of Auth."
  spec.license     = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = "Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files = Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]

  spec.add_dependency "rails", "~> 7.0.0"
  spec.add_dependency "devise"
  spec.add_dependency "doorkeeper", "~> 5.3"
  spec.add_dependency 'jwt'
  spec.add_dependency 'rotp',           '~> 6.0'
end

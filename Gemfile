source 'https://rubygems.org'
git_source(:github) { |repo| "https://github.com/#{repo}.git" }

# Specify your gem's dependencies in auth.gemspec.
gemspec

group :development do
  gem 'sqlite3'
end

# To use a debugger
gem 'byebug', group: [:development, :test]

gem "devise"
gem "doorkeeper", "~> 5.3"
gem 'jwt'
gem 'attr_encrypted', '>= 1.3', '< 4', '!= 2'
gem 'rotp',           '~> 6.0'
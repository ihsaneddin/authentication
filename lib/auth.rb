require "auth/version"
require "auth/engine"
require 'doorkeeper'
require 'jwt'
require 'plugins'

module Auth
  autoload :Configuration, "auth/configuration"
  autoload :Models, "auth/models"
  autoload :Routes, "auth/routes"
  autoload :Controllers, "auth/controllers"
  autoload :Errors, "auth/errors"
  autoload :Doorkeeper, "auth/doorkeeper"
  autoload :Grape, "auth/grape"
  autoload :Providers, "auth/providers"

  mattr_accessor :configuration
  @@configuration = Configuration

  def self.config
    @@configuration
  end

  def self.setup &block
    config.setup &block
  end

end

require 'auth/hooks'
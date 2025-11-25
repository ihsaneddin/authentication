module Auth
  module Configuration
    autoload :Api, "auth/configuration/api"
    autoload :GrapeApi, "auth/configuration/grape_api"
    autoload :Doorkeeper, "auth/configuration/doorkeeper"
    autoload :Redis, "auth/configuration/redis"

    include Plugins::Configuration::Core

    self.api= Auth::Configuration::Api
    self.grape_api= Auth::Configuration::GrapeApi

    mattr_accessor :doorkeeper
    @@doorkeeper = Doorkeeper

    mattr_accessor :application_record_base
    @@application_record_base = "Auth::ApplicationRecord"

    mattr_accessor :redis
    @@redis = Redis

    def self.application_record_base_constant
      application_record_base.constantize
    end

    def self.register_two_factor_authentication_providers *args
      args = args.map(&:constantize)
      ::Auth::Providers::TwoFactorAuthentication.register(*args)
    end

  end
end
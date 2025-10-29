module Auth
  module Configuration
    module GrapeApi

      include Plugins::Configuration::GrapeApi::Core

      self.base_api_namespace= "Auth::Grape"
      self.base_endpoint_class= "Auth::Grape::Base"

      self.authenticate = -> { false }

      mattr_accessor :prefix, :version
      self.prefix= nil

    end
  end
end
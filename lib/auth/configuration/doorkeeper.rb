module Auth
  module Configuration
    module Doorkeeper
      autoload :Extensions, "auth/configuration/doorkeeper/extensions"
      autoload :JWT, "auth/configuration/doorkeeper/jwt"

      mattr_accessor :extensions
      @@extensions = Extensions

      def self.doorkeeper
        ::Doorkeeper
      end

      def self.setup &block
        if block_given?
          doorkeeper.configure(&block)
        end
      end

      def self.config
        doorkeeper.config
      end

      def self.extensions &block
        if block_given?
          @@extensions.setup(&block)
        else
          @@extensions
        end
      end

    end
  end
end
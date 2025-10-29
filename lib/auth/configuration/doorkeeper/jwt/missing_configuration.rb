module Auth
  module Configuration
    module Doorkeeper
      module JWT
        class MissingConfiguration < StandardError
          def initialize
            super("Configuration for doorkeeper-jwt missing.")
          end
        end
      end
    end
  end
end

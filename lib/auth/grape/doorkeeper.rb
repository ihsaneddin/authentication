require 'doorkeeper/grape/helpers'

module Auth
  module Grape
    module Doorkeeper

      def self.included base
        base.class_eval do
          helpers HelperMethods
          helpers ::Doorkeeper::Grape::Helpers
        end
        base.extend ClassMethods
        # Grape::Endpoint.include HelperMethods if defined? Grape::Endpoint
        # Grape::Endpoint.include ::Doorkeeper::Grape::Helpers if defined? Grape::Endpoint
      end

      module ClassMethods

        def authenticate!
          before do
            authenticate!
          end
        end

        def skip_authentication!
          route_setting :skip_authentication, true
        end

      end

      module HelperMethods

        def authenticate!
          doorkeeper_authorize! unless route.settings[:skip_authentication]
        end

        def current_account
          @current_account ||= Auth::Account.find(doorkeeper_token.try(:resource_owner_id))
        end

      end
    end
  end
end
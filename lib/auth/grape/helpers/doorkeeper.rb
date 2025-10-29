require 'doorkeeper/grape/helpers'

module Auth
  module Grape
    module Helpers
      module Doorkeeper

        def self.included base
          base.class_eval do
            helpers HelperMethods
            helpers ::Doorkeeper::Grape::Helpers
          end
          base.extend ClassMethods
        end

        module ClassMethods

          def doorkeeper_authenticate!
            before do
              doorkeeper_authenticate!
            end
          end

          def skip_authentication!
            route_setting :skip_doorkeeper_authentication, true
          end

        end

        module HelperMethods

          def doorkeeper_authenticate!
            doorkeeper_authorize! unless route.settings[:skip_doorkeeper_authentication]
          end

          def doorkeeper_current_resource_owner
            @doorkeeper_current_resource_owner ||= doorkeeper_token.resource_owner
          end

        end
      end
    end
  end
end
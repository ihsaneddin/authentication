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

          def doorkeeper_authenticate!(*scopes)
            before do
              route_scopes = Array(route.options.dig(:doorkeeper, :scopes) || [])
              scopes = scopes + route_scopes
              doorkeeper_authenticate!(*scopes.uniq) unless skip_doorkeeper_authentication
            end
          end

          def skip_doorkeeper_authentication!
            route_setting :skip_doorkeeper_authentication, true
          end

        end

        module HelperMethods

          def doorkeeper_authenticate!(*scopes)
            unless doorkeeper_authenticate(*scopes)
              raise ::Auth::Errors::Unauthenticated, "Unauthenticated!"
            end
          end

          def doorkeeper_authenticate(*scopes)
            @_doorkeeper_scopes ||= scopes
            doorkeeper_token&.acceptable?(@_doorkeeper_scopes)
          end

          def skip_doorkeeper_authentication
            route.settings[:skip_doorkeeper_authentication]
          end

          def doorkeeper_current_resource_owner
            @doorkeeper_current_resource_owner ||= doorkeeper_token&.resource_owner
          end

        end
      end
    end
  end
end
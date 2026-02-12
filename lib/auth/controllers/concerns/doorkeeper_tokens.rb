module Auth
  module Controllers
    module Concerns
      module DoorkeeperTokens

        extend ActiveSupport::Concern

        included do

          rescue_from ::Auth::Errors::Unauthenticated  do |e|
            response_error( e.message || I18n.t("doorkeeper.errors.messages.invalid_credentials"), :forbidden)
          end

          before_action only: :create do
            unless authenticatable_class.auth_doorkeeper.grant_types.include?(params[:grant_type])
              response_error(I18n.t("doorkeeper.errors.messages.unsupported_grant_type"), :forbidden)
            end
          end

        end

        def create
          authenticate!
        rescue ::Doorkeeper::Errors::DoorkeeperError => e
          response_error(I18n.t("doorkeeper.errors.messages.invalid_credentials"), :forbidden)
        end

        def revoke
          if token.blank?
            response_error I18n.t("doorkeeper.errors.messages.invalid_token.unknown") ,:not_found
          elsif authorized?
            revoke_token
            response_success :ok, 200
          else
            response_error I18n.t("doorkeeper.errors.messages.revoke.unauthorized") ,:forbidden
          end
        end

        protected

        def authenticate!
          headers.merge!(authorize_response.headers)
          if(authorize_response.status == :ok)
            response_success authorize_response.body, authorize_response.status
          else
            response_error(authorize_response.body[:error_description] || I18n.t("doorkeeper.errors.messages.invalid_credentials"), authorize_response.status)
          end
        end

        def authenticatable_class
          name = @authenticatable_class || params[:authenticatable].presence || params[:authenticatable_class].presence
          return unless name
          @authenticatable_class ||= ::Auth::Models::Decorators::Authenticatable.registered_classes.find{|klass| klass.name == name }
          unless @authenticatable_class
            response_error(I18n.t("doorkeeper.errors.messages.invalid_credentials"), :forbidden)
          end
          @authenticatable_class
        end

        private

        def server
          @server ||= ::Doorkeeper::Server.new(self).tap do |srv|
            application = authenticatable_class&.auth_doorkeeper&.default_application(request)
            if application.is_a?(::Doorkeeper::Application) || application.is_a?(::Auth::Application)
              srv.instance_variable_set(:@client, ::Doorkeeper::OAuth::Client.new(application))
            end
          end
        end

        def resource_owner_from_credentials
          @resource_owner_from_credentials ||= authenticatable_class.auth_config.doorkeeper.resource_owner_from_credentials(request)
        end

        def response_error message="Error ocurred", status=501
          render json: { message: message }, status: status
        end

        def response_success data, status=:ok
          render json: { data: data }, status: status
        end

      end
    end
  end
end

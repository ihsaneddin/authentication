module Auth::Doorkeeper
  class SessionsController < Doorkeeper::TokensController

    include Auth::Concerns::DoorkeeperTwoFactorAuthentication

    prepend_before_action :authenticate_with_otp_two_factor,
                        if: -> { action_name == 'create' && otp_two_factor_enabled? }

    class_attribute :model
    self.model = ::Auth::Account

    before_action only: :create do
      if(params[:grant_type].nil? && !["password", "refresh_token"].include?(params[:grant_type]))
        render json:  { message: "Grant type #{params[:grant_type]} is not supported" }, status: :forbidden
      end
    end

    def create
      authenticate!
    rescue ::Doorkeeper::Errors::DoorkeeperError => e
      response_error("Invalid credentials", :forbidden)
    end

    def destroy
      if token.blank?
        response_error "Token not found" ,:not_found
      elsif authorized?
        revoke_token
        response_success :ok, 200
      else
        response_error "You are not authorized to revoke this token" ,:forbidden
      end
    end

    private
      def authenticate!
        headers.merge!(authorize_response.headers)
        if(authorize_response.status == :ok)
          response_success authorize_response.body, authorize_response.status
        else
          raise ::Doorkeeper::Errors::DoorkeeperError
        end
      end

      def resource_owner
        if resource_owner_from_credentials
          resource_owner_from_credentials
        else
          if token
            self.class.model.find token.resource_owner_id
          end
        end
      end

      def response_error message="Error ocurred", status=501
        render json: { error: message }, status: status
      end

      def response_success data, status=:ok
        render json: { data: data }, status: status
      end

      def token
        @token ||= Doorkeeper.config.access_token_model.by_token(params["token"]) ||
                   Doorkeeper.config.access_token_model.by_refresh_token(params["refresh_token"]) ||
                   doorkeeper_token
      end

  end
end
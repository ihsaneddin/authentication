module Auth
  module Concerns
    module DoorkeeperTwoFactorAuthentication
      extend ActiveSupport::Concern

      def authenticate_with_otp_two_factor
        if account_params[:otp_attempt].present? && params[:otp_session_id]
          authenticate_account_with_otp_two_factor(find_account)
        else
          prompt_for_otp_two_factor(find_account)
        end
      rescue ::Doorkeeper::Errors::DoorkeeperError => e
        response_error("Invalid credentials", :forbidden)
      end

      private

      def valid_otp_attempt?(account)
        account.validate_and_consume_otp!(account_params[:otp_attempt]) ||
            account.invalidate_otp_backup_code!(account_params[:otp_attempt])
      end

      def prompt_for_otp_two_factor(account)
        response_success({ otp_session_id: account.generate_otp_session_id! })
      end

      def authenticate_account_with_otp_two_factor(account)
        if valid_otp_attempt?(account)
          account.clear_otp_session_id
          account.save!
          @strategy = Auth::Doorkeeper::Request::OTP.new(server)
          strategy.account = account
          @authorize_response ||= begin
            before_successful_authorization
            auth = strategy.authorize
            context = build_context(auth: auth)
            after_successful_authorization(context) unless auth.is_a?(::Doorkeeper::OAuth::ErrorResponse)
            auth
          end
          headers.merge!(@authorize_response.headers)
          if(@authorize_response.status == :ok)
            response_success @authorize_response.body, @authorize_response.status
          else
            raise ::Doorkeeper::Errors::DoorkeeperError
          end
        else
          response_error("Invalid code!")
        end
      end

      def account_params
        params.permit(:otp_attempt, :otp_session_id)
      end

      def find_account
        @account ||=  if account_params[:otp_session_id]
                        Auth::Account.find_by_otp_session_id(account_params[:otp_session_id])
                      else
                        server.resource_owner
                      end
      end

      def otp_two_factor_enabled?
        find_account&.otp_required_for_login
      end

    end
  end
end
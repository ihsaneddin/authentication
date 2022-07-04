module Auth
  module Concerns
    module DeviseTwoFactorAuthentication
      extend ActiveSupport::Concern

      def authenticate_with_otp_two_factor
        user = self.resource = find_user

        if user_params[:otp_attempt].present? && session[:otp_session_id]
          authenticate_user_with_otp_two_factor(user)
        elsif user&.valid_password?(user_params[:password])
          prompt_for_otp_two_factor(user)
        end
      end

      private

      def valid_otp_attempt?(user)
        user.validate_and_consume_otp!(user_params[:otp_attempt]) ||
            user.invalidate_otp_backup_code!(user_params[:otp_attempt])
      end

      def prompt_for_otp_two_factor(user)
        @user = user

        session[:otp_session_id] = user.generate_otp_session_id!
        render 'auth/devise/sessions/two_factor'
      end

      def authenticate_user_with_otp_two_factor(user)
        if valid_otp_attempt?(user)

          session.delete(:otp_session_id)

          remember_me(user) if user_params[:remember_me] == '1'
          user.save!
          sign_in(user, event: :authentication)
        else
          flash.now[:alert] = 'Invalid two-factor code.'
          prompt_for_otp_two_factor(user)
        end
      end

      def user_params
        keys = Auth.devise.config.authentication_keys + [:password, :remember_me, :otp_attempt]
        params.require(:user).permit(*keys)
      end

      def find_user
        if session[:otp_session_id]
          User.find_by_otp_session_id(session[:otp_session_id])
        elsif authentication_key = Auth.devise.config.authentication_keys.find{|k| params[k].present }
          User.find_by(email: user_params[authentication_key])
        end
      end

      def otp_two_factor_enabled?
        find_user&.otp_required_for_login
      end

    end
  end
end
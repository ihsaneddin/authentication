module Auth
  class Account < ApplicationRecord
    # Include default devise modules. Others available are:
    # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
    devise *::Auth.devise_default_modules

    if include?(Devise::Models::TwoFactorBackupable)

      serialize :otp_backup_codes, JSON

      attr_accessor :otp_plain_backup_codes

      def two_factor_backup_codes_generated?
        otp_backup_codes.present?
      end

    end

    if include?(Devise::Models::TwoFactorAuthenticatable)

      def generate_two_factor_secret_if_missing!
        return unless otp_secret.nil?
        update!(otp_secret: self.class.generate_otp_secret)
      end

      def generate_otp_session_id!
        update!(otp_session_id: "#{id}#{SecureRandom.hex(8)}")
        otp_session_id
      end

      def clear_otp_session_id
        self.otp_session_id= nil
      end

      def clear_otp_session_id!
        update!(otp_session_id: nil)
      end

      def enable_two_factor!
        update!(otp_required_for_login: true)
      end

      def disable_two_factor!
        update!(
            otp_required_for_login: false,
            otp_secret: nil,
            otp_backup_codes: nil)
      end

    end



    if Auth.doorkeeper_enabled
      has_many :access_grants,
          class_name: 'Doorkeeper::AccessGrant',
          foreign_key: :resource_owner_id,
          dependent: :delete_all # or :destroy if you need callbacks

      has_many :access_tokens,
          class_name: 'Doorkeeper::AccessToken',
          foreign_key: :resource_owner_id,
          dependent: :delete_all # or :destroy if you need callbacks

      def generate_doorkeeper_token
        ::Doorkeeper::AccessToken.create(
          resource_owner_id: self.id,
          refresh_token: generate_refresh_token,
          expires_in: ::Doorkeeper.configuration.access_token_expires_in.to_i,
          scopes: ''
        )
      end

      def generate_refresh_token
        loop do
          token = SecureRandom.hex(32)
          break token unless ::Doorkeeper::AccessToken.exists?(refresh_token: token)
       end
      end

    end

    class << self
      #
      # @Override
      # override database authentication key
      #
      def find_for_database_authentication(warden_conditions)
        conditions = warden_conditions.dup
        login = conditions.delete(:login)
        if login.present?
          where(conditions.to_h).where([Auth.devise.authentication_keys.map{|d| "lower(#{d}) = :value" }.join(" or "), { :value => login.downcase }]).first
        elsif conditions.has_key?(:username) || conditions.has_key?(:email)
          where(conditions.to_h).first
        end
      end
    end

  end
end

module Auth
  class TwoFactorAuthenticationSession < Auth.config.application_record_base_constant

    self.table_name= "auth_two_factor_authentication_sessions"

    belongs_to :provider, class_name: "Auth::TwoFactorAuthenticationProvider", foreign_key: "provider_id"

    validates :session_uid, presence: true

    attr_accessor :current_authentication

    before_validation do
      self.session_uid ||= "#{SecureRandom.hex(8)}"
    end

    before_validation on: :create do
      self.started_at = Time.now
    end

    after_validation on: :create do
      self.expires_at ||= Time.now + 10.minutes
    end

    def attempt! max_attempts: 3, now: Time.now, &block
      raise ::Auth::Errors::TwoFactorAuthentication::SessionMaxAttemptsReached if attempts >= max_attempts
      raise ::Auth::Errors::TwoFactorAuthentication::SessionAlreadyVerified if verified_at.present?
      raise ::Auth::Errors::TwoFactorAuthentication::SessionExpired if expires_at.present? && expires_at > now
      result = yield
      increment(:attempts)
      if result
        self.verified_at= now
      end
      save(:validate => false)
      result
    end

    def expire!(now = Time.now)
      update!(expire: now)
    end

  end
end

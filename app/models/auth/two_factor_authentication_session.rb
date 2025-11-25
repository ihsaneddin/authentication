module Auth
  class TwoFactorAuthenticationSession < Auth.config.application_record_base_constant

    self.table_name= "auth_two_factor_authentication_sessions"

    include Models::Decorators::TwoFactorAuthenticationSession::Object

  end
end

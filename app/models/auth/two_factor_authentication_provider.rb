module Auth
  class TwoFactorAuthenticationProvider < Auth.config.application_record_base_constant

    self.table_name= "auth_two_factor_authentication_providers"

    include Models::Decorators::TwoFactorAuthenticationProvider::Object

  end
end

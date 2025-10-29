module Auth
  class AccessToken < Auth.config.application_record_base_constant

    include ::Doorkeeper::Orm::ActiveRecord::Mixins::AccessToken

    self.table_name= "oauth_access_tokens"

  end
end

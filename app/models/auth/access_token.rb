module Auth
  class AccessToken < Auth.config.application_record_base_constant

    include ::Doorkeeper::Orm::ActiveRecord::Mixins::AccessToken

    belongs_to :resource_owner, polymorphic: true, optional: true

    self.table_name= "oauth_access_tokens"

  end
end

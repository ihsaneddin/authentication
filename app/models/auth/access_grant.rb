module Auth
  class AccessGrant < Auth.config.application_record_base_constant

    include ::Doorkeeper::Orm::ActiveRecord::Mixins::AccessGrant

    self.table_name= "oauth_access_grants"

  end
end

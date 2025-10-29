module Auth
  class Application < Auth.config.application_record_base_constant

    include ::Doorkeeper::Orm::ActiveRecord::Mixins::Application

    self.table_name= "oauth_applications"

  end
end

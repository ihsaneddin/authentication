module Auth
  class Identity < Auth.config.application_record_base_constant

    self.table_name= "auth_identities"

    belongs_to :authenticatable, polymorphic: true

  end
end

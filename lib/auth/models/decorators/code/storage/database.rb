module Auth
  module Models
    module Decorators
      module Code
        module Storage
          module Database

            extend ::Auth::Models::Decorators::Code::Storage
            extend ActiveSupport::Concern

            included do
              # include ActiveRecord::ModelSchema
              # include ActiveRecord::ModelSchema::ClassMethods
              # extend ActiveRecord::Querying
              # include ActiveRecord::Scoping::Named
              # include ActiveRecord::Persistence
              # include ActiveRecord::ConnectionHandling

              self.table_name = "auth_codes"

              # attribute :metadata, :json, default: {}
              attribute :code_digest, :string

              validates :code, presence: true

            end

            def code= (val)
              super(val)
              self.code_digest = val
            end

            def code
              @code || self.code_digest
            end

            module ClassMethods
              def find_by_code(code)
                find_by(code_digest: code)
              end

              def connection
                ActiveRecord::Base.connection
              end

              def current_scope
                Thread.current["#{self}_current_scope"]
              end

              def all
                current_scope || unscoped
              end

              def self.current_scope
                nil
              end

            end

          end
        end
      end
    end
  end
end

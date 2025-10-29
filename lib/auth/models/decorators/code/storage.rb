module Auth
  module Models
    module Decorators
      module Code
        module Storage

          # autoload :Database, "auth/models/decorators/code/storage/database"
          # autoload :Redis, "auth/models/decorators/code/storage/redis"

          mattr_accessor :registered_storages
          @@registered_storages = Set.new

          def self.extended(mod)
            register_storage(mod)
          end

          def self.register_storage(mod)
            @@registered_storages << mod
          end

          def self.find(mod_name)
            self.registered_storages.find{|mod| mod.name.demodulize.underscore == mod_name.to_s }
          end

          require "auth/models/decorators/code/storage/database"
          require "auth/models/decorators/code/storage/redis"

        end
      end
    end
  end
end

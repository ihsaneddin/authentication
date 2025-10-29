module Auth
  module Models
    module Decorators
      module Code

        # autoload :Object, "auth/models/decorators/code/object"
        # autoload :Persistence, "auth/models/decorators/code/persistence"
        # autoload :Consumable, "auth/models/decorators/code/consumable"
        # autoload :Storage, "auth/models/decorators/code/storage"
        # autoload :Expirable, "auth/models/decorators/code/expirable"
        # autoload :Encryptable, "auth/models/decorators/code/encryptable"

        require "auth/models/decorators/code/object"
        require "auth/models/decorators/code/persistence"
        require "auth/models/decorators/code/consumable"
        require "auth/models/decorators/code/storage"
        require "auth/models/decorators/code/expirable"
        require "auth/models/decorators/code/encryptable"

      end
    end
  end
end
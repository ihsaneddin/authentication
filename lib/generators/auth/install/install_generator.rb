require "rails/generators/active_record"
module Auth
  module Generators
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration
      source_root File.join(__dir__, "templates")

      def copy_migration
        migration_template "migration.rb", "db/migrate/create_auth_module_devise_table.rb", migration_version: migration_version
        if ::Auth.doorkeeper_enabled
          migration_template "doorkeeper_migration.rb", "db/migrate/create_auth_module_doorkeeper_tables.rb", migration_version: migration_version
        end
      end

      def migration_version
        "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
      end
    end
  end
end
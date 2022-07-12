require "rails/generators/active_record"
module Auth
  module Generators
    class InstallTwoFactorGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration
      source_root File.join(__dir__, "templates")

      def copy_migration
        migration_template "migration.rb", "db/migrate/add_auth_module_two_factor_columns.rb", migration_version: migration_version
        puts "#####Message########"
        puts "Run rails db:encryption:init if you have not ran it and copy the keys to your credentials file"
        puts "####################"
      end

      def migration_version
        "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
      end
    end
  end
end
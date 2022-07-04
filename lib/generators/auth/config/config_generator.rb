module Auth
  module Generators
    class ConfigGenerator < Rails::Generators::Base
      source_root File.join(__dir__, "templates")

      def generate_config
        copy_file "auth.rb", "config/initializers/auth.rb"
      end

    end
  end
end
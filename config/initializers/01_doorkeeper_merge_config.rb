# frozen_string_literal: true
# config/initializers/doorkeeper_merge_config.rb
# Make Doorkeeper.configure additive: subsequent calls merge into the existing config
return unless defined?(Doorkeeper)
return unless Doorkeeper.respond_to?(:configure)
return unless defined?(Doorkeeper::Config::Builder)

module Doorkeeper
  module MergeConfigure
    # This replaces Doorkeeper.configure behavior for subsequent calls by merging.
    def configure(&block)
      # If @config already exists, reuse it and let the builder apply new settings on top.
      if instance_variable_defined?(:@config) && @config
        builder = Config::Builder.new
        # inject the existing config so the builder updates it instead of starting fresh
        builder.instance_variable_set(:@config, @config)
        builder.instance_eval(&block) if block
        @config = builder.build
      else
        # first-time bootstrap: call original behavior (super -> original method)
        super
      end
    rescue => e
      # fail loud during boot so you notice issues (adjust to logger you prefer)
      if defined?(Rails) && Rails.respond_to?(:logger)
        Rails.logger.error "[MyEngine] Doorkeeper.configure merge failed: #{e.class}: #{e.message}\n#{e.backtrace&.first(10)}"
      else
        warn "[MyEngine] Doorkeeper.configure merge failed: #{e.class}: #{e.message}"
      end
      raise
    end
  end
end

# Prepend once, defensive check to avoid multiple prepends
singleton = Doorkeeper.singleton_class
unless singleton.ancestors.include?(Doorkeeper::MergeConfigure)
  singleton.prepend(Doorkeeper::MergeConfigure)
end

# Doorkeeper.configure do

# end
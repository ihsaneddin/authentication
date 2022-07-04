begin; require 'grape'; rescue LoadError; end
begin; require 'grape_api'; rescue LoadError; end
if defined?(GrapeAPI::Endpoint::Base)
  require 'auth/grape/doorkeeper'
  klass = GrapeAPI::Endpoint::Base
  klass.send(:include, Auth::Grape::Doorkeeper)
else
  if defined?(Grape::API)
    require 'auth/grape/doorkeeper'

    klass = if Grape::VERSION >= '1.2.0' || defined?(Grape::API::Instance)
      Grape::API::Instance
    else
      Grape::API
    end

    klass.send(:include, Auth::Grape::Doorkeeper)
  end
end
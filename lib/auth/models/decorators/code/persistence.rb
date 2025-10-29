module Auth
  module Models
    module Decorators
      module Code
        module Persistence

          extend ::Auth::Models::Decorators::Code::Object

          def self.included base
            base.extend ClassMethods
          end

          module ClassMethods

            def storage(name)
              unless persistence?
                mod = ::Auth::Models::Decorators::Code::Storage.find(name)
                include(mod)
                define_inheritable_singleton_method(:persistence?) { true }
              end
            end

          end

        end
      end
    end
  end
end

module Auth
  module Models
    module Decorators
      module Code
        module Consumable

          extend ::Auth::Models::Decorators::Code::Object

          def self.default_options
            {
              column: "consumed_at",
              allow_reuse: false,
              on_consume: nil,
              expired: false
            }
          end

          def self.included(base)
            base.extend ClassMethods
          end

          module ClassMethods
            def consumable(**opts, &block)
              ::Auth::Models::Decorators::Code::Object.config_class.setup(
                self,
                'consumable_config',
                opts,
                ::Auth::Models::Decorators::Code::Consumable.default_options,
                method_prefix: "consumable",
                &block
              )

              attribute consumable_column.to_sym, :datetime

              define_inheritable_singleton_method(:consumable?) { true }

              include InstanceMethods
            end
          end

          module InstanceMethods
            extend ActiveSupport::Concern

            def consumed?
              send(consumable_column).present?
            end

            def consumable?
              return false if consumed? && !consumable_allow_reuse
              return false if consumable_expired
              true
            end

            def consume!(by: nil)
              return false unless consumable?

              send("#{consumable_column}=", Time.now.utc)
              save! if respond_to?(:save!)

              consumable_on_consume(by) if consumable_on_consume

              true
            end
          end

        end
      end
    end
  end
end

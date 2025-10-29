require 'set'

module Auth
  module Models
    module Decorators
      module Code
        module Object

          extend Plugins::Decorators::ConfigBuilder

          mattr_accessor :registered_classes
          mattr_accessor :registered_traits
          @@registered_classes = Set.new
          @@registered_traits  = Set.new

          def self.register_class(klass)
            @@registered_classes << klass
          end

          def self.register_trait(mod)
            @@registered_traits << mod
          end

          def self.extended(trait_mod)
            register_trait(trait_mod)
            registered_classes.each do |klass|
              include_trait_class_methods(klass, trait_mod)
              define_trait_flag_methods(klass, trait_mod)
            end
          end

          def self.include_trait_class_methods(klass, trait)
            klass.extend trait.const_get(:ClassMethods) if trait.const_defined?(:ClassMethods)
          end

          def self.define_trait_flag_methods(klass, trait)
            trait_name = if trait.respond_to?(:trait_name)
                           trait.trait_name.to_s
                         else
                           trait.name.demodulize.underscore
                         end

            method_name = "#{trait_name}?"

            ::Auth::Models::Decorators::Code.define_singleton_method trait_name do
              trait
            end

            ::Auth::Models::Decorators::Code.define_singleton_method "#{trait_name}_object" do
              trait.const_get(:InstanceMethods)
            end

            klass.define_inheritable_singleton_method(method_name) { false } unless klass.respond_to?(method_name)

            unless klass.method_defined?(method_name)
              klass.define_method(method_name) do
                self.class.send(method_name)
              end
            end
          end

          def self.included(base)
            base.extend ClassMethods
            base.include ::Plugins::Models::Concerns::Eventable::PublishesEvents
            base.include ::Plugins::Models::Concerns::ApiResource
            base.include ::Plugins.decorators.method_annotations
            base.include ::Plugins.decorators.method_decorators
            base.include ::Plugins.decorators.inheritables.singleton_methods
            base.include ::ActiveModel::Model
            base.include ::ActiveModel::Attributes
            base.include ActiveRecord::Validations
            base.include ActiveRecord::Callbacks

            base.inheritable_class_attribute :code_name
            base.class_attribute :registered_names, default: {}
            base.set_code_name

            base.include InstanceMethods
            register_class(base)
            registered_traits.each do |trait|
              include_trait_class_methods(base, trait)
              define_trait_flag_methods(base, trait)
            end

            base.attribute :code, :string
            base.attribute :session_id, :string

          end

          module ClassMethods
            def inherited(subclass)
              super(subclass)
              ::Auth::Models::Decorators::Code::Object.register_class(subclass)
              subclass.set_code_name
              mname = subclass.code_name
              base = self
              base_class.define_method "#{mname}?" do
                self.class.code_name == mname
              end
              base_class.define_method "kind_of_#{mname}?" do
                self.class <= base
              end
            end

            def set_registered_name(type, klass)
              registered_names[type.to_sym] = klass
            end

            def set_code_name(mname = name.demodulize.underscore)
              set_registered_name(mname, self)
              self.code_name = mname
            end
          end

          module InstanceMethods


          end

        end
      end
    end
  end
end
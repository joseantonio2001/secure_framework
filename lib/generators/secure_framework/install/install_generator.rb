require 'rails/generators/base'

module SecureFramework
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path('templates', __dir__)

      def install_dependencies
        # 1. Configurar Devise si es necesario
        if devise_configured?
          say "Devise already configured. Skipping Devise setup.", :yellow
        else
          say "Devise not configured yet. Running Devise setup...", :cyan
          install_devise_and_configure
        end

        # 2. Configurar Pundit si es necesario
        if pundit_configured?
          say "Pundit already configured. Skipping Pundit setup.", :yellow
        else
          say "Pundit not configured yet. Running Pundit setup...", :cyan
          install_pundit
        end

        # 3. Configurar Sanitize si es necesario
        if sanitize_configured?
          say "Sanitize already configured. Skipping Pundit setup.", :yellow
        else
          say "Sanitize not configured yet. Running Sanitize setup...", :cyan
          install_sanitize_and_configure
        end
      end     

      private

      # MÉTODOS DE COMPROBACIÓN DE GEMFILE.LOCK

      def devise_configured?
        File.exist?(File.join(destination_root, 'config/initializers/devise.rb'))
      end

      def pundit_configured?
        File.exist?(File.join(destination_root, 'app/policies/application_policy.rb'))
      end

      def sanitize_configured?
        File.exist?(File.join(destination_root, 'config/initializers/sanitize.rb'))
      end  

      # MÉTODOS DE INSTALACIÓN Y CONFIGURACIÓN (SIN CAMBIOS, SÓLO SE EJECUTAN CUANDO ES NECESARIO)
      
      def install_devise_and_configure
        say "Setting up Devise with enhanced security defaults...", :cyan

        # 1. Instalar Devise
        generate "devise:install"
        
        # 2. Aplicar políticas de seguridad modificando el archivo devise.rb
        configure_password_policy
        configure_account_locking
        migrate_secret_to_credentials

        # 3. Crear el modelo de usuario y las rutas
        generate "devise", "User", "username:string"
        route "devise_for :users"
        
        # 4. Modificar el modelo de usuario y la migración
        prepare_user_model_for_locking
        prepare_migration_for_locking

        # 5. Imprimir mensaje final
        print_success_message
      end

      def install_pundit
        say "Setting up Pundit for authorization...", :cyan
        generate "pundit:install"
        inject_into_class "app/controllers/application_controller.rb", ApplicationController do
          "  include Pundit::Authorization\n"
        end
      end
      
      def install_sanitize_and_configure
        say "Creating strict Sanitize initializer (strips all HTML tags)...", :green
        
        initializer_path = "config/initializers/sanitize.rb"
        
        create_file initializer_path, <<~RUBY
          # config/initializers/sanitize.rb
          #
          # Default configuration for the Sanitize gem, provided by secure_framework.
          # This is a strict configuration that strips all HTML tags to prevent formatting.
          # For more information on options: https://github.com/rgrove/sanitize

          Sanitize::Config::SECURE_FRAMEWORK = {
            # No HTML elements are allowed. The list is empty.
            :elements => [],

            # As an additional security measure, ensure the contents of these
            # tags are also removed, in case an external configuration allows them.
            :remove_contents => ['script', 'style']
          }
        RUBY
      end

      def configure_password_policy
        say "Applying secure password policy (12 characters minimum)...", :yellow
        gsub_file 'config/initializers/devise.rb',
                  /config\.password_length = 6\.\.128/,
                  'config.password_length = 12..128'
      end

      def configure_account_locking
        say "Enabling account locking by default...", :yellow
        # Descomentar y ajustar las opciones de bloqueo existentes para mantener la indentación
        gsub_file 'config/initializers/devise.rb', '# config.lock_strategy = :failed_attempts', 'config.lock_strategy = :failed_attempts'
        gsub_file 'config/initializers/devise.rb', '# config.unlock_strategy = :both', 'config.unlock_strategy = :time'
        gsub_file 'config/initializers/devise.rb', '# config.maximum_attempts = 20', 'config.maximum_attempts = 5'
        gsub_file 'config/initializers/devise.rb', '# config.unlock_in = 1.hour', 'config.unlock_in = 30.minutes'
      end

      def migrate_secret_to_credentials
        say "Configuring Devise to use credentials for secret_key...", :yellow
        inject_into_file 'config/initializers/devise.rb', 
                         "\n  # Load Devise secret key from encrypted credentials.\n" \
                         "  config.secret_key = Rails.application.credentials.dig(:devise, :secret_key)\n",
                         after: "Devise.setup do |config|"
        
        # Comentar la clave original si existe
        gsub_file 'config/initializers/devise.rb', /^\s*config\.secret_key = '.+'/, '# \0'
        
        say "Action required: Please run 'rails credentials:edit' to set your devise secret_key.", :red
      end
      
      def prepare_user_model_for_locking
        say "Adding :lockable module to User model...", :yellow
        gsub_file 'app/models/user.rb', 
                  /(:validatable)/, 
                  "\\1, :lockable"
      end
      
      def prepare_migration_for_locking
        say "Enabling lockable fields in the database migration...", :yellow
        migration_file = Dir.glob("db/migrate/*_devise_create_users.rb").first
        return unless migration_file

        gsub_file migration_file, /#\s*(t\.integer\s+:failed_attempts.*)/, '\1'
        gsub_file migration_file, /#\s*(t\.string\s+:unlock_token.*)/, '\1'
        gsub_file migration_file, /#\s*(t\.datetime\s+:locked_at.*)/, '\1'
        gsub_file migration_file, /#\s*(add_index :users, :unlock_token.*)/, '\1'
      end

      def print_success_message
        say "\n'secure_framework' has been successfully installed and configured!", :green
        say "\nSummary of automated actions:", :bold
        say "  ✓ Password length set to a minimum of 12 characters.", :green
        say "  ✓ Account locking enabled after 5 failed attempts.", :green
        say "  ✓ Devise secret_key configured to use Rails credentials.", :green
        say "  ✓ User model updated to include :lockable.", :green
        say "  ✓ Database migration updated for lockable fields.", :green
        
        say "\nNext steps:", :cyan
        say "  1. Run 'rails credentials:edit' and add your Devise secret_key.", :yellow
        say "  2. Run 'rails db:migrate' to apply changes to the database.", :yellow
        say "  3. Protect your controllers with 'before_action :authenticate_user!'", :yellow
      end
    end
  end
end
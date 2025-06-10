require 'rails/generators/base'

module SecureFramework
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path('templates', __dir__)

      # Orquesta la instalación y al final llama al resumen.
      def install_all_components
        run_component_installers
        print_final_summary
      end

      private

      def run_component_installers
        # 1. Configurar Gestión Segura de Secretos (AHORA ES EL PRIMER PASO)
        if secure_credentials_configured?
          say "Secure Credentials management is already configured. Skipping.", :green
        else
          say "Secure Credentials management not configured yet. Running setup...", :cyan
          install_secure_credentials
        end

        # 2. Configurar Devise si es necesario
        if devise_configured?
          say "Devise already configured. Skipping Devise setup.", :yellow
        else
          say "Devise not configured yet. Running Devise setup...", :cyan
          install_devise_and_configure
        end

        # 3. Configurar Pundit si es necesario
        if pundit_configured?
          say "Pundit already configured. Skipping Pundit setup.", :yellow
        else
          say "Pundit not configured yet. Running Pundit setup...", :cyan
          install_pundit
        end

        # 4. Configurar Sanitize si es necesario
        if sanitize_configured?
          say "Sanitize already configured. Skipping Sanitize setup.", :yellow
        else
          say "Sanitize not configured yet. Running Sanitize setup...", :cyan
          install_sanitize_and_configure
        end

        # 5. Configurar Content Security Policy (CSP) si es necesario
        if csp_configured?
          say "Content Security Policy appears to be actively configured. Skipping CSP setup.", :yellow
        else
          say "Default or unconfigured CSP detected. Applying secure policy...", :cyan
          install_csp_and_configure
        end

        # 6. Configurar Secure Headers si es necesario
        if secure_headers_configured?
          say "Secure Headers already configured. Skipping setup.", :yellow
        else
          say "Secure Headers not configured yet. Running setup...", :cyan
          install_secure_headers
        end
        
        # 7. Configurar Protección CSRF Reforzada si es necesario
        if csrf_protection_configured?
          say "CSRF protection already configured. Skipping setup.", :yellow
        else
          say "CSRF protection not configured yet. Running setup...", :cyan
          install_csrf_protection
        end
      end     

      # MÉTODOS DE COMPROBACIÓN

      def devise_configured?
        File.exist?(File.join(destination_root, 'config/initializers/devise.rb'))
      end

      def pundit_configured?
        File.exist?(File.join(destination_root, 'app/policies/application_policy.rb'))
      end

      def sanitize_configured?
        File.exist?(File.join(destination_root, 'config/initializers/sanitize.rb'))
      end

      def csp_configured?
        initializer_path = File.join(destination_root, 'config/initializers/content_security_policy.rb')
        return false unless File.exist?(initializer_path)
        content = File.read(initializer_path)
        content.match?(/^\s*policy\./)
      end
      
      def secure_headers_configured?
        File.exist?(File.join(destination_root, 'config/initializers/secure_headers.rb'))
      end
      
      def csrf_protection_configured?
        controller_path = File.join(destination_root, 'app', 'controllers', 'application_controller.rb')
        return false unless File.exist?(controller_path)
        File.read(controller_path).match?(/protect_from_forgery/)
      end
      
      def secure_credentials_configured?
        master_key_exists = File.exist?(File.join(destination_root, 'config/master.key'))
        
        gitignore_path = File.join(destination_root, '.gitignore')
        master_key_is_ignored = File.exist?(gitignore_path) && File.read(gitignore_path).include?('/config/master.key')
    
        master_key_exists && master_key_is_ignored
      end      

      # MÉTODOS DE INSTALACIÓN Y CONFIGURACIÓN (SÓLO SE EJECUTAN CUANDO ES NECESARIO)

      def install_secure_credentials

        @credentials_instructions_needed = true
    
        # Acción 1: Asegurar que master.key esté en .gitignore.
        gitignore_path = File.join(destination_root, '.gitignore')
        key_entry = '/config/master.key'
    
        # Crea .gitignore si no existe, para evitar errores.
        create_file(gitignore_path) unless File.exist?(gitignore_path)
    
        unless File.read(gitignore_path).include?(key_entry)
          say "Adding '#{key_entry}' to .gitignore...", :cyan
          append_to_file gitignore_path, "\n# Added by secure_framework to protect secrets\n#{key_entry}\n"
        end
      end       
      
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

      def install_csp_and_configure
        say "Applying secure Content Security Policy (CSP)...", :green
        initializer_path = "config/initializers/content_security_policy.rb"
        
        policy_definition = <<~RUBY
          # Be sure to restart your server when you modify this file.
          # This file was generated by the 'secure_framework' gem.

          # Define an application-wide content security policy.
          # For further information see the following documentation
          # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

          Rails.application.configure do
            config.content_security_policy do |policy|
              policy.default_src :self, :https
              policy.font_src    :self, :https, :data
              policy.img_src     :self, :https, :data
              policy.object_src  :none
              policy.script_src  :self, :https,
                                'sha256-DpVt+Ev/lTHBvE9AP6MusgWkuqGvLlkqNGv2dwHVOyE=',
                                'sha256-Bk2Ki1XPeMQgcV8U6q5OUXYdrX/47R4L1F0tatGpT7w='
              policy.style_src   :self, :https

              # Add policies for Vite in development, if the host app is using it.
              if Rails.env.development?
                # Allow @vite/client to hot reload style changes in development
                policy.style_src *policy.style_src, :unsafe_inline
                
                # Allow @vite/client to hot reload javascript changes in development,
                # but only if the ViteRuby gem is defined.
                if defined?(ViteRuby)
                  policy.script_src *policy.script_src, :unsafe_inline, "https://\#{ViteRuby.config.host_with_port}"
                end
              end

              # Specify URI for violation reports
              # policy.report_uri "/csp-violation-report-endpoint"
            end

            # Generate session nonces for permitted importmap and inline scripts
            config.content_security_policy_nonce_generator = ->(request) { request.session.id.to_s }
            config.content_security_policy_nonce_directives = %w(script-src)

            # Report CSP violations to a specified URI. See:
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
            # config.content_security_policy_report_only = true
          end
        RUBY

        remove_file(initializer_path) if File.exist?(initializer_path)
        create_file initializer_path, policy_definition
      end
      
      def install_secure_headers
        say "Creating secure_headers initializer with recommended defaults...", :green

        initializer_path = "config/initializers/secure_headers.rb"

        create_file initializer_path, <<~RUBY
          # Creado por secure_framework para centralizar la gestión de cabeceras de seguridad.

          SecureHeaders::Configuration.default do |config|
            # Previene que el sitio sea cargado en un frame o iframe (protección contra Clickjacking).
            config.x_frame_options = "SAMEORIGIN"

            # Evita que el navegador intente adivinar el tipo de contenido (MIME-type sniffing).
            config.x_content_type_options = "nosniff"

            # Activa el filtro XSS de los navegadores.
            config.x_xss_protection = "1; mode=block"

            # Previene que navegadores como IE abran descargas directamente en el contexto del sitio.
            config.x_download_options = "noopen"

            # Restringe el permiso de Adobe Flash/Reader para acceder a datos entre dominios.
            config.x_permitted_cross_domain_policies = "none"

            # Define una política más estricta sobre la información enviada en la cabecera Referer.
            config.referrer_policy = %w(origin-when-cross-origin strict-origin-when-cross-origin)

            # Desactivamos explícitamente la gestión de CSP en esta gema.
            # Esto previene cualquier conflicto con el inicializador nativo de Rails
            # (config/initializers/content_security_policy.rb) que es gestionado
            # por el método install_csp_and_configure del framework.
            config.csp = SecureHeaders::OPT_OUT

            # HTTP Strict Transport Security (HSTS)
            # Descomentar en producción para forzar conexiones HTTPS.
            # if Rails.env.production?
            #   config.strict_transport_security = "max-age=63072000; includeSubDomains"
            # end
          end
        RUBY
      end

      def install_csrf_protection
        say "Injecting reinforced CSRF protection (with: :exception)...", :green
        controller_path = "app/controllers/application_controller.rb"
        
        inject_into_file controller_path, after: "class ApplicationController < ActionController::Base\n" do
          "  protect_from_forgery with: :exception\n"
        end
      end
  
      def configure_password_policy
        say "Applying secure password policy (12 characters minimum)...", :yellow
        gsub_file 'config/initializers/devise.rb',
                  /config\.password_length = 6\.\.128/,
                  'config.password_length = 12..128'
      end

      def configure_account_locking
        say "Enabling account locking by default...", :yellow
        # Descomentar y ajustar las opciones de bloqueo existentes
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
        
        @devise_secret_instruction_needed = true
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

      def print_final_summary
        say "\n'secure_framework' has finished processing!", :green
        
        next_steps = []
        credentials_task = nil
        
        # 1. Construir dinámicamente la tarea de credentials
        if @devise_secret_instruction_needed
          # Si Devise fue instalado, la instrucción es más específica.
          credentials_task = "Run 'EDITOR=vim bin/rails credentials:edit' to set the 'secret_key' for Devise."
        elsif @credentials_instructions_needed
          # Si no, es la instrucción general.
          credentials_task = "Run 'EDITOR=vim bin/rails credentials:edit' to manage your application secrets."
        end

        # 2. Añadir la tarea de credentials al principio de la lista si es necesaria.
        next_steps.unshift(credentials_task) if credentials_task

        # 3. Añadir otras tareas si son necesarias.
        if @devise_secret_instruction_needed
          next_steps << "Run 'rails db:migrate' to apply changes to the database."
          next_steps << "Protect your controllers with 'before_action :authenticate_user!'"
        end

        # 4. Mostrar la lista final de próximos pasos si no está vacía.
        unless next_steps.empty?
          say "\nNext steps:", :cyan
          next_steps.each_with_index do |step, index|
            say "  #{index + 1}. #{step}", :yellow
          end
        end
      end
    end
  end
end
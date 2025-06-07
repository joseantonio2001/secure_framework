# secure_framework/lib/generators/secure_framework/install/install_generator.rb
module SecureFramework
  module Generators
    class InstallGenerator < Rails::Generators::Base
      
      def install_devise_and_configure
        say "Setting up Devise for secure authentication..."
        
        # 1. Instala Devise, creando config/initializers/devise.rb
        generate "devise:install"
        
        # 2. Modifica el archivo para imponer nuestra política de seguridad
        say "Applying secure password policy (12 characters minimum)...", :yellow
        gsub_file 'config/initializers/devise.rb',
                  /config\.password_length = 6\.\.128/,
                  'config.password_length = 12..128'
        
        # 3. Crea el modelo de usuario y sus rutas
        generate "devise", "User", "username:string"
        route "devise_for :users"
        
        say "Devise has been successfully set up with enhanced security defaults!", :green
        say "Next steps:", :blue
        say "1. Run 'rails db:migrate' to create the users table.", :blue
        say "2. Add 'before_action :authenticate_user!' to controllers you want to protect.", :blue
      end
    end
  end
end
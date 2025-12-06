"""
Management command to generate dummy users for testing
Usage: python manage.py generate_dummy_users [--count=75] [--role=pending]
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import datetime, timedelta
import random
import string
from PIL import Image
from io import BytesIO
from django.core.files.base import ContentFile

User = get_user_model()

class Command(BaseCommand):
    help = 'Generate dummy users for testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=75,
            help='Number of users per council (default: 75)'
        )
        parser.add_argument(
            '--role',
            type=str,
            default='pending',
            choices=['pending', 'member'],
            help='Role for dummy users (default: pending)'
        )

    def handle(self, *args, **options):
        from capstone_project.models import Council

        count = options['count']
        role = options['role']

        # Get all councils
        councils = Council.objects.all()
        if not councils.exists():
            self.stdout.write(self.style.ERROR('No councils found. Please create councils first.'))
            return

        # Data for generating realistic names
        first_names = [
            'Juan', 'Jose', 'Miguel', 'Carlos', 'Antonio', 'Francisco', 'Manuel', 'Ramon',
            'Fernando', 'Ricardo', 'Roberto', 'Sergio', 'Javier', 'Diego', 'Luis', 'Pedro',
            'Pablo', 'Andres', 'Enrique', 'Guillermo', 'Alfredo', 'Ruben', 'Hector', 'Raul',
            'Arturo', 'Julio', 'Mariano', 'Aurelio', 'Benito', 'Camilo', 'Damian', 'Eduardo',
            'Fabian', 'Gregorio', 'Ignacio', 'Joaquin', 'Leopoldo', 'Mauricio', 'Narciso',
            'Octavio', 'Pascual', 'Quintin', 'Salvador', 'Teodoro', 'Urbano', 'Vicente',
            'Wilfredo', 'Xavier', 'Ygnacio', 'Zenon'
        ]

        middle_names = [
            'Maria', 'Jose', 'de la', 'del', 'de los', 'Santos', 'Cruz', 'Luz',
            'Pilar', 'Rosa', 'Carmen', 'Dolores', 'Soledad', 'Concepcion', 'Esperanza',
            'Milagros', 'Remedios', 'Consuelo', 'Amparo', 'Graciela', 'Catalina', 'Francisca',
            'Gabriela', 'Herminia', 'Irene', 'Josefina', 'Leonor', 'Margarita', 'Natalia',
            'Ofelia', 'Paulina', 'Quintina', 'Rafaela', 'Sabina', 'Teodora', 'Ursula',
            'Valentina', 'Wanda', 'Ximena', 'Yolanda', 'Zenaida'
        ]

        last_names = [
            'Santos', 'Garcia', 'Martinez', 'Rodriguez', 'Hernandez', 'Lopez', 'Gonzalez',
            'Perez', 'Sanchez', 'Ramirez', 'Torres', 'Flores', 'Rivera', 'Morales', 'Gutierrez',
            'Ortiz', 'Jimenez', 'Reyes', 'Cruz', 'Vargas', 'Castillo', 'Romero', 'Herrera',
            'Medina', 'Aguilar', 'Vega', 'Soto', 'Fuentes', 'Campos', 'Rojas', 'Salazar',
            'Munoz', 'Navarro', 'Ramos', 'Delgado', 'Cabrera', 'Mejia', 'Acosta', 'Dominguez',
            'Carrillo', 'Ruiz', 'Pena', 'Sosa', 'Maldonado', 'Cordova', 'Pacheco', 'Quintero',
            'Valenzuela', 'Velasco', 'Velazquez', 'Vidal', 'Villarreal', 'Villegas', 'Vinales',
            'Vizcaino', 'Vivas', 'Viveros', 'Yañez', 'Zapata', 'Zarate', 'Zavala', 'Zepeda'
        ]

        occupations = [
            'Accountant', 'Architect', 'Business Owner', 'Chef/Cook', 'Civil Engineer',
            'Computer Programmer', 'Construction Worker', 'Doctor', 'Electrician', 'Engineer',
            'Farmer', 'Government Employee', 'Healthcare Worker', 'IT Professional', 'Lawyer',
            'Manager', 'Mechanic', 'Nurse', 'Police Officer', 'Retired', 'Sales Representative',
            'Security Guard', 'Student', 'Teacher', 'Technician', 'Unemployed', 'Other'
        ]

        marital_statuses = ['Single', 'Married', 'Widowed', 'Divorced', 'Separated']

        provinces = ['Batangas', 'Cavite', 'Laguna', 'Quezon', 'Rizal']

        streets = [
            'Main Street', 'Oak Avenue', 'Elm Street', 'Maple Drive', 'Pine Road',
            'Cedar Lane', 'Birch Street', 'Willow Avenue', 'Ash Drive', 'Spruce Road',
            'Walnut Street', 'Chestnut Avenue', 'Hickory Lane', 'Poplar Drive', 'Sycamore Road'
        ]

        barangays = [
            'Barangay 1', 'Barangay 2', 'Barangay 3', 'Barangay 4', 'Barangay 5',
            'Barangay 6', 'Barangay 7', 'Barangay 8', 'Barangay 9', 'Barangay 10'
        ]

        join_reasons = [
            'I want to serve the community and help those in need.',
            'I believe in the values and mission of Knights of Columbus.',
            'I want to strengthen my faith and connect with like-minded individuals.',
            'I am interested in charitable work and community service.',
            'I want to be part of a brotherhood dedicated to faith and family.',
            'I believe in supporting Catholic causes and education.',
            'I want to contribute to the development of my community.',
            'I am inspired by the organization\'s commitment to charity.',
            'I want to grow spiritually and help others do the same.',
            'I believe in the power of unity and collective action for good.'
        ]

        total_created = 0
        total_skipped = 0

        for council in councils:
            self.stdout.write(f'\nGenerating {count} users for council: {council.name}')
            
            for i in range(count):
                try:
                    # Generate unique username
                    first_name = random.choice(first_names)
                    last_name = random.choice(last_names)
                    username = f"{first_name.lower()}{last_name.lower()}{random.randint(1000, 9999)}"
                    
                    # Check if username already exists
                    if User.objects.filter(username=username).exists():
                        total_skipped += 1
                        continue
                    
                    # Generate other data
                    middle_name = random.choice(middle_names)
                    email = f"{username}@example.com"
                    password = "DummyPass123!"
                    
                    # Random birthday (age 18-70)
                    today = datetime.today().date()
                    age = random.randint(18, 70)
                    birthday = today - timedelta(days=365 * age + random.randint(0, 365))
                    
                    # Random address
                    street = f"{random.randint(1, 999)} {random.choice(streets)}"
                    province = random.choice(provinces)
                    barangay = random.choice(barangays)
                    city = f"{province} City"
                    zip_code = f"{random.randint(1000, 9999)}"
                    contact_number = f"09{random.randint(100000000, 999999999)}"
                    
                    # Create user
                    user = User.objects.create_user(
                        username=username,
                        email=email,
                        password=password,
                        role=role,
                        council=council,
                        first_name=first_name,
                        middle_name=middle_name,
                        last_name=last_name,
                        birthday=birthday,
                        street=street,
                        province=province,
                        barangay=barangay,
                        city=city,
                        zip_code=zip_code,
                        contact_number=contact_number,
                        occupation=random.choice(occupations),
                        marital_status=random.choice(marital_statuses),
                        practical_catholic=True,
                        voluntary_join=random.choice([True, False]),
                        join_reason=random.choice(join_reasons),
                        is_active=True
                    )
                    
                    # Generate a simple dummy e-signature (1x1 pixel image)
                    img = Image.new('RGB', (100, 50), color=(random.randint(100, 255), random.randint(100, 255), random.randint(100, 255)))
                    img_io = BytesIO()
                    img.save(img_io, format='PNG')
                    img_io.seek(0)
                    user.e_signature.save(f'signature_{username}.png', ContentFile(img_io.getvalue()), save=True)
                    
                    total_created += 1
                    
                    if (i + 1) % 10 == 0:
                        self.stdout.write(f'  Created {i + 1}/{count} users...')
                
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'  Error creating user: {str(e)}'))
                    total_skipped += 1
                    continue
            
            self.stdout.write(self.style.SUCCESS(f'✓ Completed for {council.name}'))

        self.stdout.write(self.style.SUCCESS(f'\n✓ Successfully created {total_created} dummy users'))
        if total_skipped > 0:
            self.stdout.write(self.style.WARNING(f'⚠ Skipped {total_skipped} users (duplicates or errors)'))
        self.stdout.write(self.style.SUCCESS(f'Total councils processed: {councils.count()}'))

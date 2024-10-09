# PawCare: A Pet Healthcare Companion Web Application for Pet Owners

![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) ![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
## Description
PawCare is a web application designed to assist pet owners in managing their pets' healthcare needs. The platform provides functionalities such as scheduling appointments, notifications for veterinary appointments, and maintaining a  health record for pets. The application aims to simplify pet healthcare management, ensuring pets receive timely and proper care.

## Installation

### Prerequisites
- Python 3.x
- Flask
- HTML
- CSS

### Steps
1. **Clone the repository:**
    ```bash
    git clone https://github.com/estif34/petco.git
    cd petco
    ```

2. **Create a virtual environment:**
    ```bash
    python -m venv venv
    ```

3. **Activate the virtual environment:**
    - On Windows:
      ```bash
      venv\Scripts\activate
      ```
    - On MacOS/Linux:
      ```bash
      source venv/bin/activate
      ```

4. **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5. **Run the application:**
    ```bash
    flask run
    ```

6. **Access the application:**
   Open your browser and navigate to `http://127.0.0.1:5000`.

## Project Structure
```markdown
petco/
│
├── __pycache__/
│
├── instance/
│
├── static/
│
├── templates/
│   ├── admin/
│   ├── base/
│   ├── emails/
│   └── forms/
│   ├── book_appointment.html
│   ├── cancel_appointment.html
│   ├── google-otp.html
│   ├── home.html
│   ├── landing.html
│   ├── login-verify.html
│   ├── my_appointments.html
│   ├── my_pets.html
│   ├── profile.html
│   ├── register_pet.html
│   ├── reschedule_appointment.html
│   ├── update_pet.html
│   └── verify.html
│
├── .env
├── .gitignore
├── app.py
├── client_credentials.py
├── client_secret.json
├── composer.json
├── mdb_index.html.txt
├── models.py
├── README.md
└── requirements.txt

# PetCo: A Pet Healthcare Companion Web Application for Kenyan Pet Owners

## Description
PetCo is a web application designed to assist Kenyan pet owners in managing their pets' healthcare needs. The platform provides functionalities such as tracking vaccination schedules, setting reminders for veterinary appointments, and maintaining a comprehensive health record for pets. The application aims to simplify pet healthcare management, ensuring pets receive timely and proper care.

## Installation

### Prerequisites
- Python 3.x
- Flask
- HTML
- CSS

### Steps
1. **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/petco.git
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
├── app/
│   ├── __init__.py
│   ├── routes.py
│   ├── models.py
│   └── static/
│       ├── css/
│       │   └── styles.css
│       └── images/
│           └── logo.png
│   └── templates/
│       ├── index.html
│       ├── layout.html
│       └── pet_details.html
│
├── tests/
│   ├── test_app.py
│   └── test_models.py
│
├── venv/
│
├── .gitignore
├── README.md
├── requirements.txt
└── run.py


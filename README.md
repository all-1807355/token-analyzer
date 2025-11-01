# Token Analyzer Web Application

This project is a **Token Analyzer** web application that leverages a **Logistic Regression Model** to analyze and classify tokens. The application is designed to identify potentially malicious or blacklisted tokens based on predefined datasets and machine learning techniques.

## Features

- **Token Analysis**: Analyze tokens to determine if they are blacklisted or potentially malicious.
- **Logistic Regression Model**: A pre-trained model (`logistic_regression_model.pkl`) is used for classification.
- **Blacklist Integration**: Includes datasets for Ethereum, Binance Smart Chain (BSC), and other blacklists.
- **Interactive Web Interface**: A user-friendly interface built with HTML, CSS, and JavaScript.
- **Dynamic Results**: Displays analysis results dynamically with visual feedback.

## Project Structure

- **`api.py`**: Backend API for handling requests and running the logistic regression model.
- **`app.py`**: Main application file to initialize and run the web server.
- **`data/`**: Contains JSON files with blacklists and other datasets.
- **`models/`**: Stores the pre-trained logistic regression model.
- **`static/`**: Contains CSS and JavaScript files for the frontend.
- **`templates/`**: HTML templates for the web interface.

## Installation

To set up and run the application locally, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/amedeoallella/thesis.git
   cd thesis/webapp
   ```

2. **Install Dependencies**:
   Ensure you have Python 3.10+ installed. Then, install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   Start the web server:
   ```bash
   python app.py
   ```

4. **Access the Application**:
   Open your browser and navigate to `http://127.0.0.1:8000`.

Alternatively:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/amedeoallella/thesis.git
   cd thesis/webapp
   ```

2. **Run the container**:
   ```bash
   docker compose up --build
   ```
   
3. **Access the Application**:
   Open your browser and navigate to `http://127.0.0.1:8000`.

## Usage

1. Upload or input a token to analyze.
2. The application will process the token using the logistic regression model.
3. Results will be displayed, including whether the token is flagged as malicious or safe.

## Datasets

The application uses the following datasets for analysis:

- **Ethereum Blacklist**: `data/ethereum-blacklist.json`
- **BSC Blacklist**: `data/bsc-blacklist.json`
- **URLs Blacklist**: `data/urls-darklist.json`
- **Locking Selectors**: `data/locking_selectors_inverted.json`

## Model

The logistic regression model (`logistic_regression_model.pkl`) was trained using labeled datasets of tokens. It evaluates tokens based on features extracted from the datasets.

## License

This project is open source and available under the [MIT License](LICENSE).

Part of a thesis project.

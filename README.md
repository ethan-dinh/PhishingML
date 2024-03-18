# README for Phishing URL Detector

## Description

This Phishing URL Detector is a Python application that uses machine learning to evaluate and predict whether a given URL is likely to be a phishing site. It combines various Python libraries to parse URLs, perform DNS and WHOIS lookups, and utilize pre-trained machine learning models for predictions.

## Features

- URL parsing to extract domain, directory, file, and parameter components.
- External lookups including DNS queries for MX records, nameserver counts, TTL of the hostname, and IP-based Autonomous System Number (ASN) retrieval.
- WHOIS lookups to determine domain activation and expiration times.
- HTTP requests to measure response time, count redirects, check for HTTPS certificates, and validate SPF records.
- Machine learning model predictions using an ensemble averaging approach with standardized input features.
- A simple terminal-based user interface to input URLs for evaluation.

## Requirements

- Python 3.x
- Libraries: `urllib`, `socket`, `dns.resolver`, `whois`, `datetime`, `joblib`, `pandas`, `requests`, `os`, `tkinter`, `numpy`, `sklearn`

Ensure that all the required libraries are installed using `pip`:
```
pip install dnspython whois requests numpy scikit-learn pandas joblib
```

For the GUI part (`tkinter`), it should be included with Python's standard library. If not, you may need to install it separately depending on your system.

## Installation

1. Clone the repository or download the source code.
2. Ensure all dependencies listed in the Requirements section are installed.
3. Place the pre-trained model file (`averaging_model.joblib`) and scaler file (`scaler.joblib`) in a directory named `Models`.

## Usage

To start the application, run the `eval.py` script from the command line:

```
python eval.py
```

Follow the prompts in the terminal to input the URL you wish to evaluate. The application will process the URL and provide a prediction along with the probability of the URL being a phishing site.

## Code Overview

- `AveragingModel`: A custom classifier that averages predictions from multiple models.
- `split_url`: Function to parse a given URL into its components.
- `calculate_url_attributes`: Function to calculate URL-based attributes.
- `get_asn`: Function to retrieve ASN information for a given IP address.
- `perform_external_lookups`: Function to perform DNS and WHOIS lookups for a given URL.
- `retrieveData`: Function to collect all relevant data for a URL.
- `predict`: Function to make predictions using the loaded model and print results.
- `initTUI`: Function to initialize the Terminal User Interface for user input.
- `main`: The main function to orchestrate the application's flow.

# Jupyter Notebook Overview
This project aims to develop a machine learning-based solution for the detection of phishing websites. The motivation stems from the need for innovative methods to combat the fast-paced evolution of phishing attacks, which outpace traditional detection techniques such as blacklisting and heuristic analysis.

## Introduction
Phishing is a critical issue in cybersecurity, where attackers seek personal and financial information through deceptive techniques. The challenge is underscored by the statistics provided by SiteCheck, which reported over 600,000 infected websites in a recent analysis. Our project leverages a proprietary dataset to discern key features that categorize websites as phishing and to create a tool that assesses the risk associated with websites.

## Contents
The notebook contains the following sections:

1. **Data Loading**: This section includes code for importing the necessary datasets for model training and testing.

2. **Data Preprocessing**: Here, we preprocess the data, which may include handling missing values, encoding categorical variables, and normalizing or scaling the features.

3. **Feature Selection**: In this part, we implement methods to select the most relevant features for the models.

4. **Model Training**: We train different machine learning models using the selected features.

5. **Hyperparameter Tuning**: The notebook demonstrates the use of GridSearchCV to find the best hyperparameters for RandomForestClassifier, XGBClassifier, and CatBoostClassifier.

6. **Ensemble Method**: An AveragingModel is implemented as an ensemble of the aforementioned classifiers to improve prediction accuracy.

7. **Model Evaluation**: This section evaluates the models and the ensemble using metrics like accuracy, ROC curves, and confusion matrices.

8. **Results Discussion**: A brief discussion interprets the model performance based on the evaluation metrics.

## Prerequisites
Before running this notebook, ensure you have the following:

- Python 3.x installed
- Jupyter Notebook or JupyterLab installed
- The required libraries installed (sklearn, xgboost, catboost, pandas, numpy, tqdm)

## Usage
To use the notebook:

1. Open the Jupyter Notebook in your preferred environment (Jupyter Notebook, JupyterLab, or an IDE with Jupyter support like VS Code).
2. Run the cells in order, from top to bottom, to replicate the model training and evaluation process.
3. You can modify hyperparameters or models as needed for further experimentation.



## Contributing
Feel free to fork this project, submit pull requests, or send us your feedback and suggestions.

## License
This project is open-sourced and available for educational and research purposes. Please provide proper attribution if you use this notebook or derived works in your projects.

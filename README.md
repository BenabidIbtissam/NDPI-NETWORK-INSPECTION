# Deep Packet Inspection App

This application is built using Python and Dash, designed to provide a practical interface for deep packet inspection. Users can either analyze a capture file or perform real-time packet inspection, with results available in CSV format.

## Features

- **File Analysis**: Analyze a provided capture file and visualize the data.
- **Real-time Capture**: Perform packet capture in real-time and display a table with protocol details and additional information.

## Files

- **app.py**: Contains the interface logic and application layout.
- **capture.py**: Includes protocol definitions and data handling.

## Requirements

To use this application, you need to install the following:

1. **Python**: [Download Python](https://www.python.org/downloads/)
2. **Dash**: Install using pip:
   
   ```bash
   pip install dash
   ```
3. **Dash**: Install using pip:
   
    ```bash
   pip install dash-bootstrap-components
   ```
    
## Running the Application

1. Clone this repository:
 ```bash
git clone <repository-url>
 ```

2.Navigate to the project directory:
 ```bash
cd <project-directory>
 ```
 
3.Run the application:
```bash
python app.py
 ```


## Usage
When you launch the application, you can choose one of two actions:

- **Analyze**: Upload a capture file to visualize the data.
- **Capture**: Start capturing packets in real-time, displaying a table with protocol information and visualizations.

## NDPI Repository
This app builds on the NDPI GitHub repository for protocol detection. You can find it here:[nDPI repo]( https://github.com/ntop/nDPI)



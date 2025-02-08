import sys
from data_analysis import analyze_data

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python app.py <data_string>')
        sys.exit(1)
    data_string = sys.argv[1]
    analyze_data(data_string)

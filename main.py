from server import *

if __name__ == '__main__':
    print('Starting server...')
    api.run(debug=True)
    print('Server shutting down.')
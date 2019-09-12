import logging

if __name__ == "__main__":
    logging.basicConfig(filename='log', format='%(asctime)s,\t%(levelname)s,\t%(message)s')
    logging.error("for test")

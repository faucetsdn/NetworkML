import numpy as np
import pickle as pickle

from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import f1_score

def main():
        print("Hello World")

        x = np.array([[1, 2, 3], [4, 5, 6]], np.int32)
        y = np.array([[1, 2, 3]], np.int32)

        print(x)
        print("---")
        print(y)

if __name__  == "__main__":
    main()
"""
Contains iterator class for generating training batches from a canned dataset
"""

import pickle
import numpy as np
from sklearn.model_selection import train_test_split

class BatchIterator:
    def __init__(
                 self,
                 data_path,
                 batch_size=64,
                 seq_len=116,
                 num_chars=16,
                 perturb_types="all",
                 seed=0
                ):
        """
        Initialize the iterator with soecified hyperparameters and load the
        data from the specified path
        """

        self.rng = np.random.RandomState(seed)

        self.classification_length = None
        self.data_path = data_path
        self.data = None
        self.sessions_by_length = None
        self.load_data()

        keys = sorted(list(self.data.keys()))
        self.train_keys, self.vala_keys = train_test_split(
                                                           keys,
                                                           test_size=0.2,
                                                           random_state=seed
                                                          )

        self.seq_len = seq_len
        self.num_chars = num_chars
        self.perturb_types = perturb_types
    def load_data(self):
        """
        Handles loading the data into the correct format
        """
        with open(self.data_path,'rb') as handle:
            data = pickle.load(handle)
        self.data = data

        sessions_by_length = [{} for i in range(9)]
        for key, value in data.items():
            for session in value:
                session_length = len(session["packets"])
                if self.classification_length is None:
                    model_output = session['model outputs']
                    classification = model_output['classification']
                    self.classification_length = len(classification)
                session_dict = sessions_by_length[session_length]
                if key not in session_dict:
                    session_dict[key] = []
                session_dict[key].append(session)
        self.sessions_by_length = sessions_by_length

    def gen_data(self, keys, length=8, batch_size=64, perturb=False):
        """
        Generates perturbed or unperturbed batches
        """
        X = np.zeros((batch_size,length,self.seq_len,self.num_chars))
        R = np.zeros((batch_size,self.classification_length))
        Y = np.zeros((batch_size,1))
        chosen_mods = []
        if perturb is True:
            Y = np.ones((batch_size,1))

        hex_str = '0123456789abcdef'
        mod_types = ['label_swap', 'packet_swap', 'duplicate']
        if self.perturb_types != "all":
            mod_types = self.perturb_types
        if length <= 1:
            mod_types = ['label_swap']

        all_keys = list(self.sessions_by_length[length].keys())
        key_subset = [key for key in keys if key in all_keys]
        chosen_keys = np.random.choice(
                                        key_subset,
                                        size=batch_size,
                                        replace=True
                                      )

        for i, key in enumerate(chosen_keys):
            if perturb is True:
                mod_type = np.random.choice(mod_types)
            else:
                mod_type = None
            chosen_mods.append(mod_type)
            sessions = self.sessions_by_length[length]
            session_id = np.random.choice(len(sessions[key]))
            session = sessions[key][session_id]
            model_outputs = session["model outputs"]

            classification = model_outputs['classification']
            classification = sorted(classification, key=lambda x: x[0])
            class_array = [p for c,p in classification]
            if mod_type == 'label_swap':
                np.random.shuffle(class_array)
            R[i] = np.asarray(class_array)

            packets = session["packets"]
            for j, packet in enumerate(packets):
                for k, char in enumerate(packet[1]):
                    if k < self.seq_len:
                        X[i,j,k,hex_str.index(char)] = 1
            if mod_type == 'packet_swap':
                id_1, id_2 = np.random.choice(range(length), size=2)
                X[i,id_1,:,:], X[i,id_2,:,:] = X[i,id_2,:,:], X[i,id_1,:,:]
            if mod_type == 'duplicate':
                id_1 = np.random.choice(range(length-1))
                id_2 = id_1 + 1
                X[i,id_2,:,:] = X[i,id_1,:,:]

        return X, R, Y, chosen_mods

    def gen_batch(self, keys, length=8, batch_size=64):
        """
        Generate mixed batches of perturbed and unperturbed data
        """
        X_g, R_g, Y_g, c_g = self.gen_data(keys, length, batch_size//2)
        X_b, R_b, Y_b, c_b = self.gen_data(keys, length, batch_size//2,
                                                                  perturb=True)
        X = np.concatenate((X_g,X_b), axis=0)
        R = np.concatenate((R_g,R_b), axis=0)
        Y = np.concatenate((Y_g,Y_b), axis=0)
        c = c_g + c_b
        return X, R, Y, c

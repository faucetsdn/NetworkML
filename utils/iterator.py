"""
Contains iterator class for generating training batches from a canned dataset
"""

import pickle
import numpy as np

class BatchIterator:
    def __init__(
                 self,
                 data_input,
                 labels,
                 batch_size=64,
                 seq_len=116,
                 num_chars=16,
                 perturb_types="all",
                 seed=0
                ):
        """
        Initialize the iterator with specified hyperparameters and load the
        data from the specified path
        """

        self.rng = np.random.RandomState(seed)

        self.data_input = data_input
        self.labels = sorted(labels)
        self.classification_length = len(labels)

        self.data = None
        self.train_sessions_by_length = None
        self.train_labels_by_length = None
        self.vala_sessions_by_length = None
        self.vala_labels_by_length = None
        self.test_sessions_by_length = None
        self.test_labels_by_length = None
        self.load_data()

        self.seq_len = seq_len
        self.num_chars = num_chars
        self.perturb_types = perturb_types

    def load_data(self):
        """
        Handles loading the data into the correct format
        """
        if type(self.data_input) is dict:
            print("Loading data from dict")
            self.data = self.data_input
        else:
            print("Loading data from disk")
            with open(self.data_input,'rb') as handle:
                data = pickle.load(handle)
            self.data = data

        train_sessions_by_length = [{} for i in range(9)]
        train_labels_by_length = [{} for i in range(9)]
        vala_sessions_by_length = [{} for i in range(9)]
        vala_labels_by_length = [{} for i in range(9)]
        test_sessions_by_length = [{} for i in range(9)]
        test_labels_by_length = [{} for i in range(9)]

        for key, value in self.data.items():
            for session in value:
                session_length = len(session["packets"])
                model_output = session['model outputs']
                class_array = [c for c,p in model_output['classification']]
                decision = class_array[0]

                # Randomly partition the data
                split = np.random.choice([1, 2, 3], p=[0.8, 0.1, 0.1])
                if split == 1:
                    session_dict = train_sessions_by_length[session_length]
                    label_dict = train_labels_by_length[session_length]
                if split == 2:
                    session_dict = vala_sessions_by_length[session_length]
                    label_dict = vala_labels_by_length[session_length]
                if split == 3:
                    session_dict = test_sessions_by_length[session_length]
                    label_dict = test_labels_by_length[session_length]

                if decision not in label_dict:
                    label_dict[decision] =0
                if decision not in session_dict:
                    session_dict[decision] = []

                session_dict[decision].append(session)
                label_dict[decision] += 1

        self.train_sessions_by_length = train_sessions_by_length
        self.train_labels_by_length = train_labels_by_length
        self.vala_sessions_by_length = vala_sessions_by_length
        self.vala_labels_by_length = vala_labels_by_length
        self.test_sessions_by_length = test_sessions_by_length
        self.test_labels_by_length = test_labels_by_length

    def gen_data(self, length=8, split='train', batch_size=64, perturb=False):
        """
        Generates perturbed or unperturbed batches
        """
        X = np.zeros((batch_size,length,self.seq_len,self.num_chars))
        L = np.zeros((batch_size,self.classification_length))
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

        if split == 'train':
            sessions_by_length = self.train_sessions_by_length
        if split == 'vala':
            sessions_by_length = self.vala_sessions_by_length
        if split == 'test':
            sessions_by_length = self.test_sessions_by_length

        all_keys = list(sessions_by_length[length].keys())
        chosen_keys = np.random.choice(
                                        all_keys,
                                        size=batch_size,
                                        replace=True
                                      )

        for i, key in enumerate(chosen_keys):
            if perturb is True:
                mod_type = np.random.choice(mod_types)
            else:
                mod_type = None
            chosen_mods.append(mod_type)
            sessions = sessions_by_length[length]
            session_id = np.random.choice(len(sessions[key]))
            session = sessions[key][session_id]
            model_outputs = session["model outputs"]

            classification = model_outputs['classification']
            classification = sorted(classification, key=lambda x: x[0])

            # Compute the label vectors using the supplied labels
            L_class = np.zeros(self.classification_length)
            indicies = [self.labels.index(c) for c, p in classification]
            probas = [p for c,p in classification]
            if mod_type == 'label_swap':
                # Shuffle the indicies for a label swap
                np.random.shuffle(indicies)
            for i, idx in enumerate(indicies):
                L_class[idx] = probas[i]

            L[i] = L_class

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


        return X, L, Y, chosen_mods

    def gen_batch(self, split='train', length=8, batch_size=64):
        """
        Generate mixed batches of perturbed and unperturbed data
        """
        X_n, L_n, Y_n, c_n = self.gen_data(
                                           length=8,
                                           split=split,
                                           batch_size=batch_size//2
                                          )
        X_a, L_a, Y_a, c_a = self.gen_data(
                                           length=8,
                                           split=split,
                                           batch_size=batch_size//2,
                                           perturb=True
                                          )
        X = np.concatenate((X_n,X_a), axis=0)
        L = np.concatenate((L_n,L_a), axis=0)
        Y = np.concatenate((Y_n,Y_a), axis=0)
        c = c_n + c_a
        return X, L, Y, c

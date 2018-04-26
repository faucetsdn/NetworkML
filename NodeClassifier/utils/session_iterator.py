"""
Contains iterator class for generating training batches from a canned dataset
"""

import pickle
import numpy as np
from sklearn.model_selection import train_test_split

class BatchIterator:
    def __init__(
                 self,
                 data_input,
                 labels,
                 batch_size=64,
                 seq_len=10,
                 ports=None,
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
        self.seq_len = seq_len
        self.data = None
        self.X = []
        self.L = []
        self.means = None
        self.stds = None
        self.sessions = []

        if ports is None:
            self.ports = [22,53,67,68,80,88,123,135,137,138,192,389,443,445,514]
        else:
            self.ports = ports
        self.feature_length = 11 + 2*len(self.ports)
        self._load_data()

        self.X_train, self.X_test, self.L_train, self.L_test = train_test_split(
                                                                self.X,
                                                                self.L,
                                                                test_size=0.2,
                                                                random_state=0
                                                                               )

        self.X_vala, self.X_test, self.L_vala, self.L_test = train_test_split(
                                                                self.X_test,
                                                                self.L_test,
                                                                test_size=0.5,
                                                                random_state=0
                                                                             )

        self.X_train = np.array(self.X_train)
        self.X_test = np.array(self.X_test)
        self.X_vala = np.array(self.X_vala)
        self.train_length = self.X_train.shape[0]
        self.validation_length = self.X_vala.shape[0]
        self.test_length = self.X_test.shape[0]
        #self._normalize()

        self.perturb_types = perturb_types

    def _load_data(self):
        """
        Handles loading the data into the correct format
        """
        if type(self.data_input) is dict:
            self.data = self.data_input
        else:
            with open(self.data_input,'rb') as handle:
                data = pickle.load(handle)
            self.data = data

        for pcap, sessions in self.data.items():
            x = np.zeros((self.seq_len, self.feature_length))
            l = np.zeros((self.classification_length, self.seq_len))
            i = 0
            session_list = []
            for session in sessions:
                session_list.append(session)
                x_sess, l_sess = self._vectorize(session)
                x[i] = x_sess
                l[:,i] = l_sess
                i += 1
                if i >= self.seq_len:
                    self.X.append(x)
                    self.L.append(np.mean(l, axis=1))
                    self.sessions.append(session_list)
                    x = np.zeros((self.seq_len, self.feature_length))
                    l = np.zeros((self.classification_length, self.seq_len))
                    i = 0
        if self.X and self.L:
            self.X = np.stack(self.X)
            self.L = np.stack(self.L)
            self.data_length = self.X.shape[0]

    def _vectorize(self, session):
        '''
        Turns a session into a feature vector
        '''

        X = np.zeros(11)
        y = np.zeros(self.classification_length)

        session_info = session['session info']

        source_port = int(session_info['source'].split(':')[1])
        destination_port = int(session_info['destination'].split(':')[1])


        # Feature for if the source initated the session
        if session_info['initiated by source']:
            X[0] = 1

        # Feature for external/internal session
        if session_info['external session']:
            X[1] = 1

        # One hot feature for the protocol
        if session_info['protocol'] == '01': # For ICMP
            X[2] = 1
        elif session_info['protocol'] == '06': # For TCP
            X[3] = 1
        elif session_info['protocol'] == '11': # For UDP
            X[4] = 1

        # Feature for amount of data sent to source/destination
        X[5] = session_info['data to source']
        X[6] = session_info['data to destination']

        # Feature for packets sent to souce/destination
        X[7] = session_info['packets to source']
        X[8] = session_info['packets to destination']

        # Feature for frequencies of source and destination
        X[9] = session_info['source frequency']
        X[10] = session_info['destination frequency']

        # Vectorize port based features
        source_ports = np.zeros(len(self.ports))
        destination_ports = np.zeros(len(self.ports))
        if source_port in self.ports and X[0] == 1:
            source_ports[self.ports.index(source_port)] = 1
        if source_port in self.ports and X[0] == 0:
            destination_ports[self.ports.index(source_port)] = 1
        if destination_port in self.ports and X[0] == 0:
            source_ports[self.ports.index(destination_port)] = 1
        if destination_port in self.ports and X[0] == 1:
            destination_ports[self.ports.index(destination_port)] = 1

        port_vec = np.concatenate([source_ports,destination_ports])
        X = np.concatenate([X,port_vec])
        # Create the labels:
        for c in session['model outputs']['classification']:
            y[self.labels.index(c[0])] = c[1]

        return X, y

    def _normalize(self):
        means = np.mean(self.X_train, axis=(0,1))
        stds = np.std(self.X_train, axis=(0,1))

        means[0:5] = 0
        means[11:] = 0
        stds[0:5] = 1
        stds[11:] = 1

        self.means = means
        self.stds = stds

    def _swap_ports(self, X):
        '''
        Swaps ports in a single session in the sequence
        '''
        s = np.random.choice(X.shape[0])
        port_len = len(self.ports)
        X_swapped = np.copy(X)
        X_swapped[s,11:port_len+11], X_swapped[s,11+port_len:] = \
        X[s,11+port_len:], X[s,11:port_len+11]
        return X_swapped

    def _switch_host(self, X):
        '''
        Switch the directionality of sessions in the sequence
        '''
        X_switched = np.copy(X)
        for i in range(X.shape[0]):
            if X[i,0] == 0:
                X_switched[i,0] = 1
            elif X[i,0] == 1:
                X_switched[i,0] = 0
        return X_switched

    def _random_data(self, X):
        '''
        Generates a sequence of random data
        '''
        X_randomized = np.copy(X)
        np.random.shuffle(X_randomized)
        for i in range(X.shape[0]):
            X_randomized[i,0] = np.random.choice([0,1])
            X_randomized[i,1] = np.random.choice([0,1])

            proto = np.random.choice([2,3,4])
            X_randomized[i, 2:5] = np.zeros(3)
            X_randomized[i, proto] = 1

            port_len = len(self.ports)
            X_randomized[i,11:port_len+11] = np.zeros(port_len)
            X_randomized[i,port_len+11:] = np.zeros(port_len)
            src = np.random.choice(range(port_len))
            dst = np.random.choice(range(port_len))
            X_randomized[i,11+src] = 1
            X_randomized[i,11+port_len+dst] = 1
        return X_randomized

    def gen_data(self, split='train', batch_size=64, perturb=False):
        """
        Generates perturbed or unperturbed batches
        """
        if split == 'validation':
            X = self.X_vala
            L = self.L_vala
            length = self.validation_length
        elif split == 'test':
            X = self.X_test
            L = self.L_test
            length = self.test_length
        elif split == 'train':
            X = self.X_train
            L = self.L_train
            length = self.train_length

        X_list = []
        L_list = []
        for i in range(batch_size):
            idx = np.random.choice(range(length))
            X_chosen = X[idx]
            #X_chosen -= self.means
            #X_chosen /= self.stds

            if perturb is True:
                perturbation = np.random.choice(self.perturb_types)
                if perturbation == 'port swap':
                    X_chosen = self._swap_ports(X_chosen)
                if perturbation == 'direction swap':
                    X_chosen = self._switch_host(X_chosen)
                if perturbation == 'random data':
                    X_chosen = self._random_data(X_chosen)
            X_list.append(X_chosen)
            L_list.append(L[idx])

        return np.stack(X_list), np.stack(L_list)

    def gen_batch(self, split='train', batch_size=64):
        """
        Generate mixed batches of perturbed and unperturbed data
        """
        X_n, L_n = self.gen_data(
                                    split=split,
                                    batch_size=batch_size
                                )
        X_a, L_a = self.gen_data(
                                    split=split,
                                    batch_size=batch_size,
                                    perturb=True
                                )
        normals = np.zeros(X_n.shape[0])
        abnormals = np.ones(X_a.shape[0])
        X = np.concatenate([X_n, X_a])
        L = np.concatenate([L_n, L_a])
        y = np.concatenate([normals, abnormals])

        return X, L, y

import functools
import numpy as np
import os
from tensorflow.python.client import device_lib
import tensorflow as tf


tf.logging.set_verbosity(tf.logging.ERROR)
os.environ['TF_CPP_MIN_LOG_LEVEL'] ='3'


def scope_decorator(function):
    """
    Decorator that handles graph construction and variable scoping
    """

    name = function.__name__
    attribute = '_cache_' + name

    @property
    @functools.wraps(function)
    def decorator(self):
        if not hasattr(self,attribute):
            with tf.variable_scope(name):
                setattr(self,attribute,function(self))
        return getattr(self,attribute)

    return decorator

def get_available_gpus():
    local_device_protos = device_lib.list_local_devices()
    return [x.name for x in local_device_protos if x.device_type == 'GPU']

def weight_variable(shape, stddev):
    """
    Creates a variable tensor with a shape defined by the input
    Inputs:
        shape: list containing dimensionality of the desired output
        stddev: standard deviation to initialize with
    """
    initial = tf.truncated_normal(shape, stddev=stddev)
    return tf.Variable(initial)

def bias_variable(shape, value=0.1):
    """
    Creates a variable tensor with dimensionality defined by the input and
    initializes it to a constant
    Inputs:
        shape: list containing dimensionality of the desired output
        value: float specifying the initial value of the variable
    """
    initial = tf.constant(value, shape=shape)
    return tf.Variable(initial)

class AbnormalDetector:
    def __init__(
                    self,
                    packet_embedding_size=100,
                    session_embedding_size=100,
                    hidden_size=100,
                    num_chars=16,
                    num_labels=32,
                    attn_size=10
                ):
        """
        Initializes the model
        """

        self.packet_embedding_size = packet_embedding_size
        self.session_embedding_size = session_embedding_size
        self.hidden_size = hidden_size
        self.num_chars = num_chars
        self.num_labels = num_labels
        self.attn_size = attn_size

        # Check for available gpus
        gpus = get_available_gpus()

        self.graph = tf.Graph()

        # Use gpu:0 if one is available
        if len(gpus) > 80:
            with self.graph.as_default():
                with tf.device(gpus[0]):
                    print("Using", gpu[0])
                    self._build_model()
        else:
            with self.graph.as_default():
                self._build_model()

        # Session config
        config = tf.ConfigProto()
        config.gpu_options.allow_growth = True

        # Create a session to run this graph
        self.sess = tf.Session(
                               config=config,
                               graph=self.graph
                              )

    def __del__(self):
        """
        Close the session when the model is deleted
        """

        self.sess.close()

    def initialize(self):
        """
        Initialize variables in the graph
        """

        with self.graph.as_default():
            self.sess.run(tf.global_variables_initializer())

    def _build_model(self):
        """
        Build the model graph
        """
        # Placeholder for learning rate
        self.lr = tf.placeholder(tf.float32)

        # Placeholder tensor for the input sessions
        self.X = tf.placeholder(
                                tf.float32,
                                [None, None, 116, self.num_chars]
                               )

        # Placeholder tensor for the input representations
        self.R = tf.placeholder(tf.float32, [None,self.num_labels])

        # Placeholder tensor for the labels/targets
        self.Y = tf.placeholder(tf.int16, [None, 1])

        # Model methods
        self.network
        self.cost
        self.optimizer
        self.get_output

        # Saver
        self.saver = tf.train.Saver()

    @scope_decorator
    def network(self):
        """
        Construct the network used for classifying sessions
        """

        # Get the shape of the input
        shape = tf.shape(self.X)

        # Reshape the packet number into batch to embed each packet separately
        X_reshaped = tf.reshape(
                                self.X,
                                [shape[0]*shape[1],shape[2],self.num_chars]
                               )

        # Embed the packets with a BLSTM  with attention
        with tf.variable_scope('packet_rnn', reuse=None):
            # Attend over the input
            packet_cell_f = tf.contrib.rnn.BasicLSTMCell(
                                                self.packet_embedding_size//2,
                                                activation=tf.tanh
                                                        )
            packet_cell_b = tf.contrib.rnn.BasicLSTMCell(
                                                self.packet_embedding_size//2,
                                                activation=tf.tanh
                                                        )
            packet_attn_cell_f = tf.contrib.rnn.AttentionCellWrapper(
                                                packet_cell_f,
                                                attn_length=self.attn_size
                                                                    )
            packet_attn_cell_b = tf.contrib.rnn.AttentionCellWrapper(
                                                packet_cell_b,
                                                attn_length=self.attn_size
                                                                    )
            packet_vectors, packet_states = tf.nn.bidirectional_dynamic_rnn(
                                                            packet_attn_cell_f,
                                                            packet_attn_cell_b,
                                                            X_reshaped,
                                                            dtype=tf.float32
                                                                           )

        packet_vectors_f = packet_vectors[0][:,-1,:]
        packet_vectors_b = packet_vectors[1][:,-1,:]
        packet_vectors = tf.concat([packet_vectors_f, packet_vectors_b],1)

        # Reshape this to recover the session dimension
        sessions = tf.reshape(
                              packet_vectors,
                              [shape[0],shape[1],self.packet_embedding_size]
                             )

        # Embed the sessions with a BLSTM with attention
        with tf.variable_scope('session_rnn', reuse=None):
            # Attend over the packets
            session_cell_f = tf.contrib.rnn.BasicLSTMCell(
                                                self.session_embedding_size//2,
                                                activation=tf.tanh
                                                         )
            session_cell_b = tf.contrib.rnn.BasicLSTMCell(
                                                self.session_embedding_size//2,
                                                activation=tf.tanh
                                                         )
            session_attn_cell_f = tf.contrib.rnn.AttentionCellWrapper(
                                                    session_cell_f,
                                                    attn_length=self.attn_size
                                                                     )
            session_attn_cell_b = tf.contrib.rnn.AttentionCellWrapper(
                                                    session_cell_b,
                                                    attn_length=self.attn_size
                                                                     )
            session_vectors, session_states = tf.nn.bidirectional_dynamic_rnn(
                                                            session_attn_cell_f,
                                                            session_attn_cell_b,
                                                            sessions,
                                                            dtype=tf.float32
                                                                             )

        session_vectors_f = session_vectors[0][:,-1,:]
        session_vectors_b = session_vectors[1][:,-1,:]
        session_vectors = tf.concat([session_vectors_f, session_vectors_b],1)

        # Pass the RNN output through a feedforward layer
        std_dev = np.sqrt(2)/np.sqrt(
                                self.session_embedding_size+self.hidden_size
                                    )
        weights_1 = weight_variable(
                                [self.session_embedding_size,self.hidden_size],
                                std_dev
                                   )
        biases_1 = bias_variable([self.hidden_size], value=0.0)
        layer_1 = tf.matmul(session_vectors,weights_1) + biases_1
        layer_1 = tf.nn.tanh(layer_1)

        # Compute the weighted average over the class vectors
        std_dev = np.sqrt(2)/np.sqrt(self.hidden_size + 1)
        class_vectors = weight_variable(
                                        [self.hidden_size,self.num_labels],
                                        std_dev
                                       )
        class_biases = bias_variable([self.num_labels],value=0.0)

        R = tf.expand_dims(self.R, axis=1)
        classes = tf.expand_dims(class_vectors, axis=0)
        biases = tf.expand_dims(class_biases,axis=0)

        RC = R*classes
        RB = self.R*biases

        weighted_classes = tf.reduce_sum(RC, axis=2)
        weighted_bias = tf.reduce_sum(RB,axis=1)

        output = weighted_classes * layer_1
        output = tf.reduce_sum(output, axis=1)
        output = output + weighted_bias
        output = tf.expand_dims(output, axis=1)
        probs = tf.nn.sigmoid(output)

        return output, probs

    @scope_decorator
    def cost(self):
        """
        Binary cross entropy cost
        """
        output, _ = self.network
        cost = tf.losses.sigmoid_cross_entropy(self.Y, output)
        return cost

    @scope_decorator
    def optimizer(self):
        """
        Constructs the optimizer op used to train the network.
        Use gradient clipping.
        """
        opt = tf.train.AdamOptimizer()
        gradients, variables = zip(*opt.compute_gradients(self.cost))
        gradients, _ = tf.clip_by_global_norm(gradients, 0.01)
        return opt.apply_gradients(zip(gradients, variables))

    def save(self, path):
        """
        Saves the model to the specified path.
        """
        self.saver.save(self.sess, path)

    def load(self, path):
        """
        Load the model from the specified path.
        """
        self.saver.restore(self.sess, path)

    def train_on_batch(self, X, R, Y, learning_rate=0.01):
        """
        Train model for one step on specified batch
        """
        c, _ = self.sess.run([self.cost, self.optimizer],
                             {
                                self.X: X,
                                self.R: R,
                                self.Y: Y,
                                self.lr: learning_rate
                             }
                            )
        return c

    def get_cost(self, X, R, Y):
        """
        Get the cost on a specified batch
        """
        c = self.sess.run(
                            self.cost,
                                {
                                 self.X: X,
                                 self.R: R,
                                 self.Y: Y
                                }
                         )
        return c

    def get_output(self, X, R):
        """
        Get the predictions given input data
        """
        _, out = self.sess.run(
                                self.network,
                                    {
                                        self.X: X,
                                        self.R: R
                                    }
                              )

        return out

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

class SoSModel:
    def __init__(
                    self,
                    feature_size=41,
                    label_size=21,
                    rnn_size=100,
                ):
        """
        Initializes the model
        """

        self.feature_size = feature_size
        self.label_size = label_size
        self.rnn_size = rnn_size

        # Check for available gpus
        gpus = get_available_gpus()

        self.graph = tf.Graph()

        # Use gpu:0 if one is available
        if len(gpus) > 0:
            with self.graph.as_default():
                with tf.device(gpus[0]):
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
                                [None, None, self.feature_size]
                               )

        # Placeholder tensor for the input representations
        self.L = tf.placeholder(tf.float32, [None,self.label_size])

        # Placeholder tensor for the labels/targets
        self.Y = tf.placeholder(tf.float32, [None])

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

        # Embed the session sequence with an LSTM with attention
        with tf.variable_scope('session_rnn', reuse=None):
            session_cell = tf.contrib.rnn.BasicLSTMCell(
                                                self.rnn_size,
                                                activation=tf.tanh
                                                         )

            session_vectors, session_states = tf.nn.dynamic_rnn(
                                                                session_cell,
                                                                self.X,
                                                                dtype=tf.float32
                                                               )
        # session_vectors should be (batch_size, time_step, rnn_size)
        # Reshape to (batch_size*time_step, rnn_size) to calc outputs
        vectors = tf.reshape(session_vectors, (shape[0]*shape[1],self.rnn_size))

        # Pass the vectors through a feedforward layer
        std_dev = np.sqrt(2)/np.sqrt(self.rnn_size+self.label_size)
        weights_1 = weight_variable([self.rnn_size,self.label_size],std_dev)
        biases_1 = bias_variable([self.label_size], value=0.0)
        layer_1 = tf.matmul(vectors,weights_1) + biases_1
        layer_1 = layer_1
        layer_1 = tf.reshape(layer_1, (shape[0],shape[1],self.label_size))

        # Compute the weighted average over the class vectors
        class_vectors = tf.expand_dims(self.L, axis=1)
        weighted_average = tf.reduce_sum(layer_1*class_vectors, axis=2)

        return weighted_average[:,-1], tf.sigmoid(weighted_average)

    @scope_decorator
    def cost(self):
        """
        Binary cross entropy cost
        """
        output, _ = self.network
        cost = tf.nn.sigmoid_cross_entropy_with_logits(
                                                        labels=self.Y,
                                                        logits=output
                                                      )
        return tf.reduce_mean(cost)

    @scope_decorator
    def optimizer(self):
        """
        Constructs the optimizer op used to train the network.
        Use gradient clipping.
        """
        opt = tf.train.AdamOptimizer()
        #gradients, variables = zip(*opt.compute_gradients(self.cost))
        #gradients, _ = tf.clip_by_global_norm(gradients, 0.1)
        #return opt.apply_gradients(zip(gradients, variables))
        return opt.minimize(self.cost)

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

    def train_on_batch(self, X, L, Y, learning_rate=0.01):
        """
        Train model for one step on specified batch
        """
        c, _ = self.sess.run([self.cost, self.optimizer],
                             {
                                self.X: X,
                                self.L: L,
                                self.Y: Y,
                                self.lr: learning_rate
                             }
                            )
        return c

    def get_cost(self, X, L, Y):
        """
        Get the cost on a specified batch
        """
        c = self.sess.run(
                            self.cost,
                                {
                                 self.X: X,
                                 self.L: L,
                                 self.Y: Y
                                }
                         )
        return c

    def get_output(self, X, L):
        """
        Get the predictions given input data
        """
        _, out = self.sess.run(
                                self.network,
                                    {
                                        self.X: X,
                                        self.L: L
                                    }
                              )

        return out
